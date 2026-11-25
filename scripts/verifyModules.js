/**
 * Structural check for every backend module.
 *
 * Catches problems such as a declaration accidentally nested inside another
 * block, which would still parse as valid JavaScript but would leave an
 * export undefined or a route unregistered.
 *
 * Run with:  npm run verify
 */
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env.local') });
dotenv.config();

const root = path.join(__dirname, '..');
const problems = [];

const requireFunction = (label, value, expectedName) => {
    if (typeof value !== 'function') {
        problems.push(`${label}.${expectedName} is ${typeof value}, expected function`);
        return false;
    }
    return true;
};

const requireNonEmptyArray = (label, value, expectedName) => {
    if (!Array.isArray(value)) {
        problems.push(`${label}.${expectedName} is ${typeof value}, expected array`);
        return false;
    }
    if (!value.length) {
        problems.push(`${label}.${expectedName} is an empty array`);
        return false;
    }
    return true;
};

// --- models ---------------------------------------------------------------
const models = require(path.join(root, 'models'));
['User', 'Order', 'Medicine', 'Doctor', 'Appointment', 'Article', 'Review', 'Cart'].forEach((name) => {
    if (!models[name]) problems.push(`models.${name} is undefined`);
});
requireFunction('models', models.normalizeEmail, 'normalizeEmail');
requireFunction('models', models.findUserByEmail, 'findUserByEmail');

// --- middleware/auth ------------------------------------------------------
const auth = require(path.join(root, 'middleware', 'auth'));
['requireAuth', 'requireAdmin', 'requireOwnerOrAdmin'].forEach((name) => {
    requireFunction('middleware/auth', auth[name], name);
});

// --- middleware/firebase --------------------------------------------------
const firebase = require(path.join(root, 'middleware', 'firebase'));
['getJwtSecret', 'initializeFirebaseAdmin', 'isFirebaseReady', 'verifyFirebaseIdToken',
    'extractBearerToken', 'resolveAuthenticatedUser'].forEach((name) => {
    requireFunction('middleware/firebase', firebase[name], name);
});

// --- middleware/rateLimiter -----------------------------------------------
const rateLimiter = require(path.join(root, 'middleware', 'rateLimiter'));
['authLimiter', 'orderLimiter', 'bookingLimiter', 'paymentLimiter', 'reviewLimiter', 'writeLimiter'].forEach((name) => {
    requireFunction('middleware/rateLimiter', rateLimiter[name], name);
});

// --- middleware/validators ------------------------------------------------
const validators = require(path.join(root, 'middleware', 'validators'));
['handleValidation', 'isValidObjectId', 'sanitizeEmail'].forEach((name) => {
    requireFunction('middleware/validators', validators[name], name);
});
Object.keys(validators).forEach((name) => {
    if (['handleValidation', 'isValidObjectId', 'sanitizeEmail'].includes(name)) return;
    requireNonEmptyArray('middleware/validators', validators[name], name);
});

// --- routes ---------------------------------------------------------------
['auth', 'catalog', 'appointments', 'commerce', 'assistant'].forEach((name) => {
    const router = require(path.join(root, 'routes', name));
    requireFunction(`routes/${name}`, router, 'router');
});

// --- report ---------------------------------------------------------------
const lines = [];
lines.push('MODULE STRUCTURE CHECK');
lines.push('='.repeat(60));
if (problems.length) {
    problems.forEach((p) => lines.push(`❌ ${p}`));
} else {
    lines.push('✅ All modules export the expected members.');
}
lines.push('='.repeat(60));
lines.push(problems.length ? `${problems.length} problem(s) found.` : 'No problems found.');

console.log(lines.join('\n'));
process.exit(problems.length ? 1 : 0);
