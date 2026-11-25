/**
 * Validates the Firebase Admin credentials WITHOUT ever printing the private key.
 *
 * Run with:  node scripts/checkFirebaseSetup.js
 */
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env.local') });
dotenv.config();

const { isFirebaseReady, initializeFirebaseAdmin } = require(path.join(__dirname, '..', 'middleware', 'firebase'));

const keyPathEnv = process.env.GOOGLE_APPLICATION_CREDENTIALS;
const lines = [];

lines.push('FIREBASE ADMIN SETUP CHECK');
lines.push('='.repeat(60));

if (!keyPathEnv) {
    lines.push('❌ GOOGLE_APPLICATION_CREDENTIALS is not set.');
    lines.push('   Add it to .env.local (see .env.example).');
    console.log(lines.join('\n'));
    process.exit(1);
}

const keyPath = path.resolve(process.cwd(), keyPathEnv);
lines.push(`GOOGLE_APPLICATION_CREDENTIALS : ${keyPathEnv}`);
lines.push(`Resolved path                 : ${keyPath}`);

if (!fs.existsSync(keyPath)) {
    lines.push('❌ The service account key file does not exist.');
    console.log(lines.join('\n'));
    process.exit(1);
}

lines.push('✅ Key file exists');

// Read only the non-secret metadata. The private key is never printed.
let key;
try {
    key = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
} catch (err) {
    lines.push(`❌ The key file is not valid JSON: ${err.message}`);
    console.log(lines.join('\n'));
    process.exit(1);
}

lines.push('✅ Key file is valid JSON');
lines.push(`   type        : ${key.type}`);
lines.push(`   project_id  : ${key.project_id}`);
lines.push(`   client_email: ${key.client_email}`);
lines.push(`   private_key : ${key.private_key ? 'present (not printed)' : 'MISSING'}`);

const required = ['type', 'project_id', 'private_key', 'client_email'];
const missing = required.filter((field) => !key[field]);
if (missing.length) {
    lines.push(`❌ Missing required fields: ${missing.join(', ')}`);
    console.log(lines.join('\n'));
    process.exit(1);
}

// Initialise the Admin SDK for real.
const ok = initializeFirebaseAdmin();
lines.push('');
lines.push(ok
    ? '✅ Firebase Admin SDK initialised successfully.'
    : '❌ Firebase Admin SDK failed to initialise.');

if (!ok) {
    console.log(lines.join('\n'));
    process.exit(1);
}

// Prove that token verification is actually wired up by sending a bogus token.
const { verifyFirebaseIdToken } = require(path.join(__dirname, '..', 'middleware', 'firebase'));
verifyFirebaseIdToken('definitely-not-a-real-firebase-id-token')
    .then(() => {
        lines.push('❌ A bogus token was accepted - this should never happen!');
        console.log(lines.join('\n'));
        process.exit(1);
    })
    .catch((err) => {
        lines.push(`✅ Bogus token correctly rejected (${err.code || err.message.split('\n')[0]})`);
        lines.push('='.repeat(60));
        console.log(lines.join('\n'));
        process.exit(0);
    });
