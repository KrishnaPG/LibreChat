import { logger, getTenantId, tenantStorage } from '@librechat/data-schemas';
import type { OpenIdRoleSyncClaimSource } from './openidRoleSync';
import { getOpenIdRolesForOpenIdSync } from './openidRoleSync';
import { isEnabled } from '~/utils';

/** Groups created and reconciled by this sync; groups of any other source are never touched. */
export const OPENID_GROUP_SOURCE = 'oidc';

const DEFAULT_CLAIM = 'realm_access.roles';
const DEFAULT_CLAIM_SOURCE: OpenIdRoleSyncClaimSource = 'access';
const DEFAULT_MAX_GROUPS = 100;
const REGEX_PREFIX = 'regex:';

export type OpenIdGroupSyncOptions = {
  enabled: boolean;
  claimSource: OpenIdRoleSyncClaimSource;
  claim: string;
  maxGroups: number;
  isExcluded: (groupName: string) => boolean;
};

/** Token material available to a sync; a source that is absent leaves memberships unchanged. */
export type OpenIdGroupSyncTokens = {
  accessToken?: string;
  idToken?: string;
  claims?: unknown;
  userinfo?: unknown;
};

export type OpenIdGroupSyncUser = {
  _id?: { toString(): string } | string | null;
  idOnTheSource?: string | null;
  tenantId?: string | null;
};

export type OpenIdGroupSyncMethods = {
  findGroupsByExternalIds: (
    idsOnTheSource: string[],
    source: typeof OPENID_GROUP_SOURCE,
  ) => Promise<Array<{ idOnTheSource?: string | null }>>;
  upsertGroupByExternalId: (
    idOnTheSource: string,
    source: typeof OPENID_GROUP_SOURCE,
    updateData: { name: string },
  ) => Promise<unknown>;
  bulkUpdateGroups: (
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
  ) => Promise<{ modifiedCount?: number }>;
};

export type OpenIdGroupSyncResult = {
  created: number;
  added: number;
  removed: number;
};

function parseExcludePatterns(raw: string | undefined): (groupName: string) => boolean {
  const entries =
    raw
      ?.split(',')
      .map((entry) => entry.trim())
      .filter(Boolean) ?? [];
  const exact = new Set(entries.filter((entry) => !entry.startsWith(REGEX_PREFIX)));
  const patterns = entries
    .filter((entry) => entry.startsWith(REGEX_PREFIX))
    .map((entry) => {
      const source = entry.slice(REGEX_PREFIX.length);
      try {
        return new RegExp(source);
      } catch {
        throw new Error(
          `[openidGroupSync] OPENID_GROUPS_EXCLUDE_PATTERN has an invalid regex: ${source}`,
        );
      }
    });
  return (groupName) => exact.has(groupName) || patterns.some((pattern) => pattern.test(groupName));
}

/**
 * Reads and validates the OPENID_SYNC_GROUPS_FROM_TOKEN / OPENID_GROUPS_* configuration.
 * A disabled sync never fails on stale or mistyped settings.
 */
export function getOpenIdGroupSyncOptions(
  env: NodeJS.ProcessEnv = process.env,
): OpenIdGroupSyncOptions {
  const enabled = isEnabled(env.OPENID_SYNC_GROUPS_FROM_TOKEN);
  const claimSource = (env.OPENID_GROUPS_TOKEN_KIND?.trim() ||
    DEFAULT_CLAIM_SOURCE) as OpenIdRoleSyncClaimSource;
  const claim = env.OPENID_GROUPS_CLAIM_PATH?.trim() || DEFAULT_CLAIM;
  const rawMax = env.OPENID_MAX_GROUPS_PER_USER?.trim();
  const parsedMax = rawMax ? Number(rawMax) : DEFAULT_MAX_GROUPS;

  if (!enabled) {
    return { enabled, claimSource, claim, maxGroups: DEFAULT_MAX_GROUPS, isExcluded: () => false };
  }

  if (!['access', 'id', 'userinfo'].includes(claimSource)) {
    throw new Error(
      '[openidGroupSync] OPENID_GROUPS_TOKEN_KIND must be one of: access, id, userinfo',
    );
  }

  if (!Number.isInteger(parsedMax) || parsedMax <= 0) {
    throw new Error('[openidGroupSync] OPENID_MAX_GROUPS_PER_USER must be a positive integer');
  }

  return {
    enabled,
    claimSource,
    claim,
    maxGroups: parsedMax,
    isExcluded: parseExcludePatterns(env.OPENID_GROUPS_EXCLUDE_PATTERN),
  };
}

/** Normalizes claim values to unique, trimmed, non-excluded group identifiers. */
export function getOpenIdGroupNames(
  values: string | unknown[],
  isExcluded: (groupName: string) => boolean,
): string[] {
  const list = Array.isArray(values) ? values : values.split(/[\s,]+/);
  const names = new Set<string>();
  for (const value of list) {
    if (typeof value !== 'string') {
      continue;
    }
    const name = value.trim();
    if (name && !isExcluded(name)) {
      names.add(name);
    }
  }
  return [...names];
}

function isDuplicateKeyError(error: unknown): boolean {
  return (error as { code?: number } | undefined)?.code === 11000;
}

/**
 * Makes the `oidc` groups a member belongs to equal `groupNames`: missing groups are created,
 * the member is added to every listed group and removed from every other `oidc` group.
 * Groups of other sources (`local`, `entra`) are never read or written. Runs in the ambient
 * tenant context, so lookups, creations and removals stay inside the caller's tenant.
 */
export async function reconcileOpenIdGroupMemberships({
  memberId,
  groupNames,
  methods,
}: {
  memberId: string;
  groupNames: string[];
  methods: OpenIdGroupSyncMethods;
}): Promise<OpenIdGroupSyncResult> {
  let created = 0;
  let added = 0;

  if (groupNames.length > 0) {
    const existing = await methods.findGroupsByExternalIds(groupNames, OPENID_GROUP_SOURCE);
    const existingIds = new Set(existing.map((group) => group.idOnTheSource));
    const missing = groupNames.filter((name) => !existingIds.has(name));

    /** A concurrent login may create the same group first; its unique index then rejects ours. */
    const upserts = await Promise.all(
      missing.map((name) =>
        methods
          .upsertGroupByExternalId(name, OPENID_GROUP_SOURCE, { name })
          .then(() => true)
          .catch((error: unknown) => {
            if (isDuplicateKeyError(error)) {
              return false;
            }
            throw error;
          }),
      ),
    );
    created = upserts.filter(Boolean).length;

    const addResult = await methods.bulkUpdateGroups(
      {
        source: OPENID_GROUP_SOURCE,
        idOnTheSource: { $in: groupNames },
        memberIds: { $ne: memberId },
      },
      { $addToSet: { memberIds: memberId } },
    );
    added = addResult.modifiedCount ?? 0;
  }

  const removeResult = await methods.bulkUpdateGroups(
    {
      source: OPENID_GROUP_SOURCE,
      memberIds: memberId,
      idOnTheSource: { $nin: groupNames },
    },
    { $pullAll: { memberIds: [memberId] } },
  );

  return { created, added, removed: removeResult.modifiedCount ?? 0 };
}

/**
 * Creates the OpenID token-claim group sync. The returned function is called after a login and
 * after an OpenID token refresh; it is fail-open, so an error is logged and never blocks
 * authentication.
 */
export function createOpenIdGroupSync({
  methods,
  decodeToken,
  env = process.env,
}: {
  methods: OpenIdGroupSyncMethods;
  decodeToken: (token: string) => unknown;
  env?: NodeJS.ProcessEnv;
}) {
  async function syncWithOptions(
    user: OpenIdGroupSyncUser,
    tokens: OpenIdGroupSyncTokens,
    options: OpenIdGroupSyncOptions,
  ): Promise<OpenIdGroupSyncResult | undefined> {
    const values = await getOpenIdRolesForOpenIdSync({ options, decodeToken, ...tokens });
    if (values === undefined) {
      logger.debug(
        `[openidGroupSync] Skipped for user ${user._id}; the '${options.claimSource}' claim source is unavailable`,
      );
      return;
    }

    const groupNames = getOpenIdGroupNames(values, options.isExcluded);
    if (groupNames.length > options.maxGroups) {
      logger.warn(
        `[openidGroupSync] Skipped for user ${user._id}; ${groupNames.length} groups exceed OPENID_MAX_GROUPS_PER_USER (${options.maxGroups})`,
      );
      return;
    }

    const memberId = user.idOnTheSource || String(user._id);
    const result = await reconcileOpenIdGroupMemberships({ memberId, groupNames, methods });
    logger.debug(
      `[openidGroupSync] User ${user._id}: ${groupNames.length} groups, ${result.created} created, ${result.added} added, ${result.removed} removed`,
    );
    return result;
  }

  return async function syncUserOpenIdGroups(
    user: OpenIdGroupSyncUser | null | undefined,
    tokens: OpenIdGroupSyncTokens,
  ): Promise<OpenIdGroupSyncResult | undefined> {
    try {
      const options = getOpenIdGroupSyncOptions(env);
      if (!options.enabled || !user?._id) {
        return;
      }

      const tenantId = user.tenantId ? String(user.tenantId) : undefined;
      if (!tenantId || getTenantId() != null) {
        return await syncWithOptions(user, tokens, options);
      }
      /** The OAuth callback runs before the tenant middleware; scope the sync to the user's tenant. */
      return await tenantStorage.run({ tenantId, userId: String(user._id) }, async () =>
        syncWithOptions(user, tokens, options),
      );
    } catch (error) {
      logger.error('[openidGroupSync] Error syncing OpenID groups:', error);
      return;
    }
  };
}

export type SyncUserOpenIdGroups = ReturnType<typeof createOpenIdGroupSync>;
