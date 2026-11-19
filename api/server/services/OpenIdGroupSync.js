const jwtDecode = require('jsonwebtoken/decode');
const { createOpenIdGroupSync } = require('@librechat/api');
const db = require('~/models');

const syncUserOpenIdGroups = createOpenIdGroupSync({
  methods: {
    findGroupsByExternalIds: (...args) => db.findGroupsByExternalIds(...args),
    upsertGroupByExternalId: (...args) => db.upsertGroupByExternalId(...args),
    bulkUpdateGroups: (...args) => db.bulkUpdateGroups(...args),
  },
  decodeToken: jwtDecode,
});

module.exports = { syncUserOpenIdGroups };
