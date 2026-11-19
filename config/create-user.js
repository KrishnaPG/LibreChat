const path = require('path');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { createModels, tenantStorage } = require('@librechat/data-schemas');
const { User } = createModels(mongoose);
require('module-alias')({ base: path.resolve(__dirname, '..', 'api') });
const { registerUser } = require('~/server/services/AuthService');
const { askQuestion, silentExit } = require('./helpers');
const connect = require('./connect');

(async () => {
  await connect();

  console.purple('--------------------------');
  console.purple('Create a new user account!');
  console.purple('--------------------------');

  if (process.argv.length < 5) {
    console.orange('Usage: npm run create-user -- <email> <name> <username> [--email-verified=false]');
    console.orange('Note: if you do not pass in the arguments, you will be prompted for them.');
    console.orange(
      'If you really need to pass in the password, you can do so as the 4th argument (not recommended for security).',
    );
    console.orange('Use --email-verified=false to set emailVerified to false. Default is true.');
    console.purple('--------------------------');
  }

  // Parse command line arguments
  let email, password, name, username, emailVerified, provider, tenantId;
  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i].startsWith('--email-verified=')) {
      emailVerified = process.argv[i].split('=')[1].toLowerCase() !== 'false';
      continue;
    }

    if (process.argv[i].startsWith('--provider=')) {
      provider = process.argv[i].split('=')[1];
      continue;
    }

    if (process.argv[i].startsWith('--tenant=')) {
      tenantId = process.argv[i].slice('--tenant='.length).trim();
      if (!tenantId) {
        console.red('Error: --tenant needs a tenant id.');
        silentExit(1);
      }
      continue;
    }

    if (email === undefined) {
      email = process.argv[i];
    } else if (name === undefined) {
      name = process.argv[i];
    } else if (username === undefined) {
      username = process.argv[i];
    } else if (password === undefined) {
      console.red('Warning: password passed in as argument, this is not secure!');
      password = process.argv[i];
    }
  }

  if (email === undefined) {
    email = await askQuestion('Email:');
  }
  if (!email.includes('@')) {
    console.red('Error: Invalid email address!');
    silentExit(1);
  }

  const defaultName = email.split('@')[0];
  if (name === undefined) {
    name = await askQuestion('Name: (default is: ' + defaultName + ')');
    if (!name) {
      name = defaultName;
    }
  }
  if (username === undefined) {
    username = await askQuestion('Username: (default is: ' + defaultName + ')');
    if (!username) {
      username = defaultName;
    }
  }
  // An account of another provider (e.g. openid) signs in there: it gets an unusable random password and no prompt.
  if (password === undefined && provider !== undefined && provider !== 'local') {
    password = crypto.randomBytes(24).toString('base64url');
  }
  if (password === undefined) {
    password = await askQuestion('Password: (leave blank, to generate one)');
    if (!password) {
      password = Math.random().toString(36).slice(-18);
      console.orange('Your password is: ' + password);
    }
  }

  // Only prompt for emailVerified if it wasn't set via CLI
  if (emailVerified === undefined) {
    const emailVerifiedInput = await askQuestion(`Email verified? (Y/n, default is Y):

If \`y\`, the user's email will be considered verified.
      
If \`n\`, and email service is configured, the user will be sent a verification email.

If \`n\`, and email service is not configured, you must have the \`ALLOW_UNVERIFIED_EMAIL_LOGIN\` .env variable set to true,
or the user will need to attempt logging in to have a verification link sent to them.`);

    const normalizedEmailVerifiedInput = emailVerifiedInput.trim().toLowerCase()

    emailVerified = true

    if (normalizedEmailVerifiedInput === 'n') {
      emailVerified = false;
    }
  }

  // Inside a tenant context, lookups are scoped to the tenant and the new user is stamped with it,
  // so the account can be bound where a tenant is required (Agent Management API clients).
  const inTenant = (fn) => (tenantId ? tenantStorage.run({ tenantId }, fn) : fn());
  await inTenant(() => createAccount({ email, password, name, username, emailVerified, provider }));
})();

async function createAccount({ email, password, name, username, emailVerified, provider }) {
  const userExists = await User.findOne({ $or: [{ email }, { username }] });
  if (userExists) {
    // Re-running the same provisioning is a success, so a declarative Job can run it again.
    if (userExists.email === email && userExists.username === username && (userExists.provider ?? 'local') === (provider ?? 'local')) {
      console.green('User already exists.');
      silentExit(0);
    }
    console.red('Error: A user with that email or username already exists!');
    silentExit(1);
  }

  const user = { email, password, name, username, confirm_password: password };
  const additionalData = { emailVerified, ...(provider !== undefined ? { provider } : {}) };
  let result;
  try {
    result = await registerUser(user, additionalData);
  } catch (error) {
    console.red('Error: ' + error.message);
    silentExit(1);
  }

  if (result.status !== 200) {
    console.red('Error: ' + result.message);
    silentExit(1);
  }

  const userCreated = await User.findOne({ $or: [{ email }, { username }] });
  if (userCreated) {
    console.green('User created successfully!');
    console.green(`Email verified: ${userCreated.emailVerified}`);
    silentExit(0);
  }
}

process.on('uncaughtException', (err) => {
  if (!err.message.includes('fetch failed')) {
    console.error('There was an uncaught error:');
    console.error(err);
  }

  if (err.message.includes('fetch failed')) {
    return;
  } else {
    process.exit(1);
  }
});
