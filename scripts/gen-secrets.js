'use strict';

// Prints a fresh MASTER_KEY and SESSION_SECRET for .env:
//
//   npm run gen-secrets            (or: node scripts/gen-secrets.js)
//
// Only the two KEY=value lines go to stdout, so `node scripts/gen-secrets.js >> .env`
// appends them cleanly; the notes go to stderr. Nothing is written or stored.
//
// Replacing MASTER_KEY on an installation that already holds data makes every
// stored SMTP password, legacy API key and 2FA secret unreadable unless the old
// key stays in MASTER_KEY_PREVIOUS until scripts/rotate-master-key.js has run
// (README, "Rotating the master key"). Replacing SESSION_SECRET only signs every
// admin out.

const { randomHex, randomBase64Url } = require('../src/lib/crypto');
const { parseMasterKey } = require('../src/config');

const USAGE = `Usage: node scripts/gen-secrets.js

Prints two lines to paste into .env:
  MASTER_KEY      32 random bytes as 64 hex characters (encrypts stored secrets)
  SESSION_SECRET  48 random bytes, base64url (signs admin session cookies)
`;

function generate() {
  const masterKey = randomHex(32);
  const sessionSecret = randomBase64Url(48);

  // Self-check against the parser the app uses, so a printed key is always accepted.
  const problems = [];
  const parsed = parseMasterKey(masterKey, 'MASTER_KEY', problems);
  if (!parsed || problems.length) throw new Error('generated MASTER_KEY failed validation: ' + problems.join('; '));
  if (sessionSecret.length < 32) throw new Error('generated SESSION_SECRET is too short');

  return { masterKey, sessionSecret };
}

function main(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv.length) {
    process.stderr.write(`gen-secrets: unexpected argument ${argv[0]}\n\n${USAGE}`);
    return 2;
  }

  const { masterKey, sessionSecret } = generate();
  process.stdout.write(`MASTER_KEY=${masterKey}\nSESSION_SECRET=${sessionSecret}\n`);
  process.stderr.write(
    [
      '',
      'Paste these into .env (chmod 600). Never commit them, email them or put them in the cPanel UI.',
      'Keep a copy of MASTER_KEY with your .env backup: without it, stored SMTP passwords,',
      'legacy API keys and 2FA secrets cannot be decrypted, even from a database backup.',
      'Already running? Do not just replace MASTER_KEY; follow "Rotating the master key" in README.md.',
      '',
    ].join('\n')
  );
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`gen-secrets: ${err && err.message ? err.message : err}\n`);
  process.exitCode = 1;
}
