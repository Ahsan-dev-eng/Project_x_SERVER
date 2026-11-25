const { getApps, initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const { User, normalizeEmail, findUserByEmail } = require('../models');

let firebaseApp = null;
let firebaseReady = false;
let firebaseInitAttempted = false;

/**
 * Returns the secret used to sign the legacy session JWTs.
 * There is deliberately no insecure default: the server refuses to start when
 * JWT_SECRET is missing so that a shipped instance can never sign tokens with
 * a well known key.
 */
const getJwtSecret = () => {
    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 32) {
        throw new Error('JWT_SECRET is missing or too short. Set a strong random value in .env.local.');
    }
    return secret;
};

/**
 * Initialises the Firebase Admin SDK.
 *
 * Credentials are resolved in this order:
 *   1. GOOGLE_APPLICATION_CREDENTIALS - path to a git-ignored service account key file.
 *   2. FIREBASE_SERVICE_ACCOUNT      - the service account JSON supplied directly as an
 *                                      environment variable (used by deployments).
 *
 * When neither is present the SDK stays disabled and the server logs a clear
 * warning. Auth endpoints then fail closed with 401 - they never accept an
 * unverified token.
 */
const initializeFirebaseAdmin = () => {
    if (firebaseInitAttempted) return firebaseReady;
    firebaseInitAttempted = true;

    try {
        const existingApps = getApps();
        if (existingApps.length) {
            firebaseApp = existingApps[0];
            firebaseReady = true;
            return true;
        }

        const serviceAccountEnv = process.env.FIREBASE_SERVICE_ACCOUNT;
        const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;

        let credential;
        if (serviceAccountEnv) {
            // Deployment mode: the service account JSON is injected as an env var.
            const parsed = typeof serviceAccountEnv === 'string'
                ? JSON.parse(serviceAccountEnv)
                : serviceAccountEnv;
            credential = cert(parsed);
            console.log('✅ Firebase Admin SDK initialised (FIREBASE_SERVICE_ACCOUNT)');
        } else if (credentialsPath) {
            // Local mode: path to the git-ignored service account key file.
            const resolved = path.resolve(process.cwd(), credentialsPath);
            if (!fs.existsSync(resolved)) {
                throw new Error(`Service account key file not found at "${resolved}".`);
            }
            credential = cert(resolved);
            console.log('✅ Firebase Admin SDK initialised (GOOGLE_APPLICATION_CREDENTIALS)');
        } else {
            throw new Error('Neither GOOGLE_APPLICATION_CREDENTIALS nor FIREBASE_SERVICE_ACCOUNT is configured.');
        }

        firebaseApp = initializeApp({ credential });
        firebaseReady = true;
        return true;
    } catch (err) {
        firebaseReady = false;
        console.error('❌ Firebase Admin SDK initialisation failed:', err.message);
        console.error('   Firebase ID token verification is disabled. Place serviceAccountKey.json in the backend');
        console.error('   root and set GOOGLE_APPLICATION_CREDENTIALS in .env.local to enable it.');
        return false;
    }
};

const isFirebaseReady = () => firebaseReady;

/**
 * Verifies a Firebase ID token with the Admin SDK.
 * Throws when the SDK is unavailable or the token is invalid/expired/revoked.
 */
const verifyFirebaseIdToken = async (token) => {
    if (!initializeFirebaseAdmin()) {
        throw new Error('Firebase Admin SDK is not configured on this server.');
    }
    return getAuth(firebaseApp).verifyIdToken(token);
};

/**
 * Pulls the raw token out of an `Authorization: Bearer <token>` header.
 */
const extractBearerToken = (req) => {
    const header = req.headers.authorization || '';
    const [scheme, value] = header.split(' ');
    if (!scheme || scheme.toLowerCase() !== 'bearer' || !value) return null;
    return value.trim();
};

/**
 * Resolves the caller from either credential type, supporting the transition
 * between the legacy session JWT and native Firebase ID tokens.
 *
 * Order of resolution:
 *   1. Firebase ID token  -> verified with admin.auth().verifyIdToken()
 *   2. Legacy session JWT -> verified with jsonwebtoken using JWT_SECRET
 *
 * Returns `{ user, source, claims }` on success, or `null` when the token is
 * missing, malformed, expired or does not map to a known user.
 */
const resolveAuthenticatedUser = async (token) => {
    if (!token) return null;

    // 1. Native Firebase ID token.
    if (isFirebaseReady()) {
        try {
            const decoded = await verifyFirebaseIdToken(token);
            const email = normalizeEmail(decoded.email);
            if (!email) return null;

            let user = await findUserByEmail(email);
            if (!user) {
                // The account exists in Firebase but has not been registered in the
                // backend yet - create it with the lowest possible privilege.
                user = new User({
                    email,
                    name: decoded.name || email,
                    role: 'User',
                    firebaseUid: decoded.uid,
                });
                await user.save();
                console.log(`👤 Auto-provisioned backend user for ${email}`);
            } else if (!user.firebaseUid) {
                user.firebaseUid = decoded.uid;
                await user.save();
            }

            return { user, source: 'firebase', claims: decoded };
        } catch (err) {
            // Not a valid Firebase ID token - fall through to the legacy JWT check.
        }
    }

    // 2. Legacy session JWT issued by POST /login.
    try {
        const decoded = jwt.verify(token, getJwtSecret());
        const user = await findUserByEmail(decoded.email);
        if (!user) return null;
        return { user, source: 'session', claims: decoded };
    } catch (err) {
        return null;
    }
};

module.exports = {
    getJwtSecret,
    initializeFirebaseAdmin,
    isFirebaseReady,
    verifyFirebaseIdToken,
    extractBearerToken,
    resolveAuthenticatedUser,
};
