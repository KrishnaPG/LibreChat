import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { createModels, createMethods, tenantStorage } from '@librechat/data-schemas';
import type { IGroup } from '@librechat/data-schemas';
import type { OpenIdGroupSyncMethods } from './openidGroupSync';
import {
  getOpenIdGroupSyncOptions,
  createOpenIdGroupSync,
  getOpenIdGroupNames,
  OPENID_GROUP_SOURCE,
} from './openidGroupSync';

const ENABLED_ENV = {
  OPENID_SYNC_GROUPS_FROM_TOKEN: 'true',
  OPENID_GROUPS_TOKEN_KIND: 'access',
  OPENID_GROUPS_CLAIM_PATH: 'groups',
};

/** The sync decodes claims only; the OpenID client has already verified the token. */
const token = (payload: Record<string, unknown>) => jwt.sign(payload, 'test-secret');
const accessToken = (groups?: unknown) => token(groups === undefined ? { sub: 'x' } : { groups });

let mongo: MongoMemoryServer;
let methods: ReturnType<typeof createMethods>;
let Group: mongoose.Model<IGroup>;

const syncMethods = (): OpenIdGroupSyncMethods => ({
  findGroupsByExternalIds: (ids, source) => methods.findGroupsByExternalIds(ids, source),
  upsertGroupByExternalId: (id, source, data) => methods.upsertGroupByExternalId(id, source, data),
  bulkUpdateGroups: (filter, update) => methods.bulkUpdateGroups(filter, update),
});

const createSync = (env: NodeJS.ProcessEnv = ENABLED_ENV) =>
  createOpenIdGroupSync({ methods: syncMethods(), decodeToken: (t) => jwt.decode(t), env });

const membersOf = async (filter: Record<string, unknown>) => {
  const groups = await Group.find(filter).lean();
  return Object.fromEntries(groups.map((g) => [g.idOnTheSource ?? g.name, g.memberIds ?? []]));
};

const runAsTenant = <T>(tenantId: string, fn: () => Promise<T>) =>
  tenantStorage.run({ tenantId }, fn);

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  createModels(mongoose);
  await mongoose.connect(mongo.getUri());
  methods = createMethods(mongoose);
  Group = mongoose.models.Group as mongoose.Model<IGroup>;
  await Group.syncIndexes();
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
});

afterEach(async () => {
  await Group.deleteMany({});
});

describe('getOpenIdGroupSyncOptions', () => {
  it('is disabled by default and ignores stale settings while disabled', () => {
    const options = getOpenIdGroupSyncOptions({
      OPENID_GROUPS_TOKEN_KIND: 'bogus',
      OPENID_MAX_GROUPS_PER_USER: '-5',
      OPENID_GROUPS_EXCLUDE_PATTERN: 'regex:(',
    });
    expect(options.enabled).toBe(false);
  });

  it('defaults to the access token and realm_access.roles', () => {
    const options = getOpenIdGroupSyncOptions({ OPENID_SYNC_GROUPS_FROM_TOKEN: 'true' });
    expect(options).toMatchObject({
      enabled: true,
      claimSource: 'access',
      claim: 'realm_access.roles',
      maxGroups: 100,
    });
  });

  it.each([
    ['OPENID_GROUPS_TOKEN_KIND', 'refresh'],
    ['OPENID_MAX_GROUPS_PER_USER', '-5'],
    ['OPENID_MAX_GROUPS_PER_USER', '0'],
    ['OPENID_MAX_GROUPS_PER_USER', 'many'],
    ['OPENID_GROUPS_EXCLUDE_PATTERN', 'regex:('],
  ])('rejects %s=%s when enabled', (key, value) => {
    expect(() => getOpenIdGroupSyncOptions({ ...ENABLED_ENV, [key]: value })).toThrow(
      '[openidGroupSync]',
    );
  });

  it('excludes exact names and regex patterns', () => {
    const { isExcluded } = getOpenIdGroupSyncOptions({
      ...ENABLED_ENV,
      OPENID_GROUPS_EXCLUDE_PATTERN: 'offline_access, regex:^default-roles-',
    });
    expect(isExcluded('offline_access')).toBe(true);
    expect(isExcluded('default-roles-acme')).toBe(true);
    expect(isExcluded('course-101')).toBe(false);
  });
});

describe('getOpenIdGroupNames', () => {
  it('trims, de-duplicates, drops non-strings and applies exclusions', () => {
    expect(
      getOpenIdGroupNames([' a ', 'a', 'b', 3, null, '', 'skip'], (name) => name === 'skip'),
    ).toEqual(['a', 'b']);
  });

  it('splits a string claim on spaces and commas', () => {
    expect(getOpenIdGroupNames('a, b c', () => false)).toEqual(['a', 'b', 'c']);
  });
});

describe('createOpenIdGroupSync with MongoDB', () => {
  const user = { _id: new mongoose.Types.ObjectId(), idOnTheSource: 'kc-user-1' };

  it('creates missing groups and adds the member at login', async () => {
    const result = await createSync()(user, {
      accessToken: accessToken(['/course-a', '/course-b']),
    });

    expect(result).toEqual({ created: 2, added: 2, removed: 0 });
    const groups = await Group.find({ source: OPENID_GROUP_SOURCE }).lean();
    expect(groups.map((g) => [g.idOnTheSource, g.name, g.memberIds])).toEqual(
      expect.arrayContaining([
        ['/course-a', '/course-a', ['kc-user-1']],
        ['/course-b', '/course-b', ['kc-user-1']],
      ]),
    );
  });

  it('removes the member from a group dropped from the claim at refresh, keeping other members', async () => {
    const sync = createSync();
    const other = { _id: new mongoose.Types.ObjectId(), idOnTheSource: 'kc-user-2' };
    await sync(user, { accessToken: accessToken(['/course-a', '/course-b']) });
    await sync(other, { accessToken: accessToken(['/course-b']) });

    const result = await sync(user, { accessToken: accessToken(['/course-a']) });

    expect(result).toEqual({ created: 0, added: 0, removed: 1 });
    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({
      '/course-a': ['kc-user-1'],
      '/course-b': ['kc-user-2'],
    });
  });

  it('never changes local or entra groups, even with the same name', async () => {
    await Group.create([
      { name: 'manual', source: 'local', memberIds: ['kc-user-1'] },
      { name: '/course-a', source: 'local', memberIds: ['kc-user-1'] },
      { name: 'Entra', source: 'entra', idOnTheSource: '/course-a', memberIds: ['kc-user-1'] },
    ]);
    const sync = createSync();

    await sync(user, { accessToken: accessToken(['/course-a']) });
    await sync(user, { accessToken: accessToken([]) });

    const untouched = await Group.find({ source: { $in: ['local', 'entra'] } }).lean();
    expect(untouched).toHaveLength(3);
    expect(untouched.every((g) => g.memberIds?.includes('kc-user-1'))).toBe(true);
    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({ '/course-a': [] });
  });

  it('removes every oidc membership when a present token has no groups claim', async () => {
    const sync = createSync();
    await sync(user, { accessToken: accessToken(['/course-a']) });

    const result = await sync(user, { accessToken: accessToken() });

    expect(result).toEqual({ created: 0, added: 0, removed: 1 });
  });

  it('changes nothing when the configured token is unavailable', async () => {
    const sync = createSync();
    await sync(user, { accessToken: accessToken(['/course-a']) });

    expect(await sync(user, { idToken: token({ groups: [] }) })).toBeUndefined();
    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({
      '/course-a': ['kc-user-1'],
    });
  });

  it('reads the id token and userinfo when configured', async () => {
    const idSync = createSync({ ...ENABLED_ENV, OPENID_GROUPS_TOKEN_KIND: 'id' });
    await idSync(user, { idToken: token({ groups: ['/from-id'] }) });
    const userinfoSync = createSync({ ...ENABLED_ENV, OPENID_GROUPS_TOKEN_KIND: 'userinfo' });
    await userinfoSync(user, { userinfo: { groups: ['/from-id', '/from-userinfo'] } });

    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({
      '/from-id': ['kc-user-1'],
      '/from-userinfo': ['kc-user-1'],
    });
  });

  it('reads a nested claim path and applies exclusions', async () => {
    const sync = createSync({
      ...ENABLED_ENV,
      OPENID_GROUPS_CLAIM_PATH: 'realm_access.roles',
      OPENID_GROUPS_EXCLUDE_PATTERN: 'offline_access,regex:^default-roles-',
    });

    await sync(user, {
      accessToken: token({
        realm_access: { roles: ['course-a', 'offline_access', 'default-roles-acme'] },
      }),
    });

    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({ 'course-a': ['kc-user-1'] });
  });

  it('joins an admin-created oidc group without renaming it', async () => {
    await Group.create({ name: 'Course A', source: 'oidc', idOnTheSource: '/course-a' });

    await createSync()(user, { accessToken: accessToken(['/course-a']) });

    const group = await Group.findOne({ idOnTheSource: '/course-a' }).lean();
    expect(group).toMatchObject({ name: 'Course A', memberIds: ['kc-user-1'] });
  });

  it('keys members by user id when the user has no idOnTheSource', async () => {
    const localKeyed = { _id: new mongoose.Types.ObjectId() };

    await createSync()(localKeyed, { accessToken: accessToken(['/course-a']) });

    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({
      '/course-a': [localKeyed._id.toString()],
    });
  });

  it('skips a claim with more groups than OPENID_MAX_GROUPS_PER_USER', async () => {
    const sync = createSync({ ...ENABLED_ENV, OPENID_MAX_GROUPS_PER_USER: '2' });
    await sync(user, { accessToken: accessToken(['/a']) });

    expect(await sync(user, { accessToken: accessToken(['/b', '/c', '/d']) })).toBeUndefined();
    expect(await membersOf({ source: OPENID_GROUP_SOURCE })).toEqual({ '/a': ['kc-user-1'] });
  });

  it('does nothing when disabled', async () => {
    const result = await createSync({})(user, { accessToken: accessToken(['/course-a']) });

    expect(result).toBeUndefined();
    expect(await Group.countDocuments({})).toBe(0);
  });

  it('keeps groups and memberships inside the user tenant', async () => {
    const sync = createSync();
    const inA = { ...user, tenantId: 'tenant-a' };
    const inB = { ...user, tenantId: 'tenant-b' };

    await sync(inA, { accessToken: accessToken(['/course-a']) });
    await sync(inB, { accessToken: accessToken(['/course-a']) });
    await sync(inA, { accessToken: accessToken([]) });

    const groups = await Group.find({ idOnTheSource: '/course-a' }).lean();
    expect(groups.map((g) => [g.tenantId, g.memberIds]).sort()).toEqual([
      ['tenant-a', []],
      ['tenant-b', ['kc-user-1']],
    ]);
  });

  it('uses the ambient tenant context when one is already set', async () => {
    await runAsTenant('tenant-a', () =>
      createSync()({ ...user, tenantId: 'tenant-a' }, { accessToken: accessToken(['/course-a']) }),
    );

    const group = await Group.findOne({ idOnTheSource: '/course-a' }).lean();
    expect(group?.tenantId).toBe('tenant-a');
  });

  it('treats a concurrent first creation of the same group as success', async () => {
    const other = { _id: new mongoose.Types.ObjectId(), idOnTheSource: 'kc-user-2' };
    const sync = createSync();

    await Promise.all([
      sync(user, { accessToken: accessToken(['/course-a']) }),
      sync(other, { accessToken: accessToken(['/course-a']) }),
    ]);

    const groups = await Group.find({ idOnTheSource: '/course-a' }).lean();
    expect(groups).toHaveLength(1);
    expect([...(groups[0].memberIds ?? [])].sort()).toEqual(['kc-user-1', 'kc-user-2']);
  });
});
