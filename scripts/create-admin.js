'use strict';

// Creates an admin, or resets the password of an existing one:
//
//   node scripts/create-admin.js <email> [--name "Full Name"] [--reset-2fa]
//
// In a terminal the password is asked for twice without echo. Without a
// terminal (cPanel "Run JS script", cron) it is read from RELAY_ADMIN_PASSWORD;
// unset that variable afterwards. A reset signs the admin out everywhere;
// --reset-2fa also turns off their two-factor authentication (lost device).
// Changes are audited with the "system" actor. Exit code 1 on any error.

const { loadConfig, ConfigError } = require('../src/config');
const { createDb } = require('../src/db');
const { createLogger, describeError } = require('../src/lib/logger');
const { systemClock } = require('../src/lib/time');
const { HttpError } = require('../src/lib/errors');
const { getAdminByEmail } = require('../src/repos/admins');
const { SYSTEM_ACTOR } = require('../src/services/audit');
const admins = require('../src/services/admins');

const USAGE = `Usage: node scripts/create-admin.js <email> [--name "Full Name"] [--reset-2fa]

Creates the admin, or resets the password if the email already exists.
The password is prompted for (twice, not shown) when run in a terminal;
otherwise set RELAY_ADMIN_PASSWORD for this one command.
  --name "X"     display name (also updates an existing admin's name)
  --reset-2fa    when resetting, also turn off two-factor authentication
`;

class CliError extends Error {}

function parseArgs(argv) {
  const out = { email: null, name: undefined, reset2fa: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--reset-2fa') out.reset2fa = true;
    else if (a === '--name') {
      if (i + 1 >= argv.length) throw new CliError('--name needs a value');
      out.name = argv[++i];
    } else if (a.startsWith('--name=')) out.name = a.slice('--name='.length);
    else if (a.startsWith('-')) throw new CliError(`unknown option ${a}`);
    else if (out.email === null) out.email = a;
    else throw new CliError(`unexpected argument ${a}`);
  }
  return out;
}

// Reads one line from the terminal in raw mode, printing nothing for the typed
// characters. Handles backspace, Ctrl+C (cancel) and pasted text.
function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = Boolean(stdin.isRaw);
    let value = '';
    process.stderr.write(prompt);

    function done(err) {
      stdin.removeListener('data', onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
      process.stderr.write('\n');
      if (err) reject(err);
      else resolve(value);
    }

    function onData(chunk) {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') return done(new CliError('cancelled'));
        if (ch === '\u0004') return value === '' ? done(new CliError('cancelled')) : done();
        if (ch === '\u007f' || ch === '\b') {
          value = Array.from(value).slice(0, -1).join('');
          continue;
        }
        // Arrow keys and other escape sequences arrive as one chunk: drop it.
        if (ch === '\u001b') break;
        if (ch < ' ') continue;
        value += ch;
      }
    }

    stdin.setEncoding('utf8');
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

async function readPassword() {
  const fromEnv = process.env.RELAY_ADMIN_PASSWORD;
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv;
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') {
    throw new CliError(
      'no terminal to ask for the password; set RELAY_ADMIN_PASSWORD for this command ' +
        '(on Git Bash/mintty, run it through winpty or from cmd/PowerShell)'
    );
  }
  const first = await readHidden('New password: ');
  const problem = admins.validatePassword(first);
  if (problem) throw new CliError(problem);
  const second = await readHidden('Repeat the password: ');
  if (first !== second) throw new CliError('the two passwords do not match');
  return first;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (!args.email) throw new CliError(`an email address is required\n\n${USAGE}`);
  const email = admins.normalizeEmail(args.email);
  if (!admins.isValidAdminEmail(email)) throw new CliError(`"${args.email}" is not a valid email address`);

  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) throw new CliError(err.message);
    throw err;
  }

  const password = await readPassword();
  const problem = admins.validatePassword(password);
  if (problem) throw new CliError(problem);

  const db = createDb(config.db);
  const deps = { config, db, clock: systemClock, logger: createLogger({ file: config.logFile }) };
  try {
    const existing = await getAdminByEmail(db, email);
    if (!existing) {
      const id = await admins.createAdmin(deps, { email, name: args.name || '', password, actor: SYSTEM_ACTOR });
      process.stdout.write(`Admin ${email} created (id ${id}). Sign in at ${config.publicBaseUrl}/admin\n`);
      return;
    }

    await admins.setPassword(deps, { adminId: existing.id, password, actor: SYSTEM_ACTOR, reset: true });
    process.stdout.write(`Password reset for ${email}; their existing sessions were signed out.\n`);
    if (args.name !== undefined && (await admins.setName(deps, { adminId: existing.id, name: args.name, actor: SYSTEM_ACTOR }))) {
      process.stdout.write('Name updated.\n');
    }
    if (args.reset2fa) {
      if (existing.totpEnabled || existing.totpSecretEnc) {
        await admins.disableTotp(deps, { adminId: existing.id, actor: SYSTEM_ACTOR });
        process.stdout.write('Two-factor authentication turned off; they can set it up again under Account.\n');
      } else {
        process.stdout.write('Two-factor authentication was already off.\n');
      }
    } else if (existing.totpEnabled) {
      process.stdout.write('Two-factor authentication is still on (use --reset-2fa if the device is lost).\n');
    }
    if (existing.disabled) {
      process.stderr.write('Warning: this admin is disabled; another admin must enable it under Users.\n');
    }
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((err) => {
  let message;
  if (err instanceof CliError || err instanceof HttpError) message = err.message;
  // Database and network errors. describeError adds the code and copes with an
  // AggregateError whose message is empty (DB_HOST=localhost tried on ::1 and 127.0.0.1).
  else if (err && (err.code || err.errors)) message = describeError(err);
  else message = err && err.stack ? err.stack : String(err);
  process.stderr.write(`create-admin: ${message}\n`);
  process.exitCode = 1;
});
