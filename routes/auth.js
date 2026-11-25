const express = require('express');
const jwt = require('jsonwebtoken');

const { User, normalizeEmail, findUserByEmail } = require('../models');
const { requireAuth, requireAdmin, requireOwnerOrAdmin } = require('../middleware/auth');
const { getJwtSecret, verifyFirebaseIdToken, isFirebaseReady } = require('../middleware/firebase');
const { authLimiter, writeLimiter } = require('../middleware/rateLimiter');
const {
    handleValidation,
    loginValidation,
    userCreateValidation,
    makeAdminValidation,
} = require('../middleware/validators');

const router = express.Router();

/**
 * POST /login
 *
 * Exchanges a Firebase ID token for the legacy session JWT.
 * The Firebase ID token is VERIFIED with the Admin SDK before any session
 * token is issued - the supplied email is never trusted on its own.
 */
router.post('/login', authLimiter, loginValidation, handleValidation, async (req, res) => {
    const { email, firebaseToken } = req.body;

    if (!isFirebaseReady()) {
        return res.status(503).json({ error: 'Authentication service is not configured on this server.' });
    }

    let decoded;
    try {
        decoded = await verifyFirebaseIdToken(firebaseToken);
    } catch (err) {
        console.error('Firebase token verification failed:', err.message);
        return res.status(401).json({ error: 'Invalid or expired Firebase token' });
    }

    if (normalizeEmail(decoded.email) !== normalizeEmail(email)) {
        return res.status(401).json({ error: 'Firebase token does not match the provided email' });
    }

    try {
        const user = await findUserByEmail(email);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const token = jwt.sign({ email: user.email }, getJwtSecret(), { expiresIn: '1h' });
        return res.json({ token, admin: user.role === 'Admin' });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Error logging in' });
    }
});

/**
 * POST /users
 *
 * Registers a user. The role is ALWAYS forced to 'User' on the server so a
 * client can never self-elevate to Admin. Administrators are promoted through
 * PUT /users/admin only.
 */
router.post('/users', authLimiter, userCreateValidation, handleValidation, async (req, res) => {
    const { email, name } = req.body;
    try {
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        const user = new User({ email, name, role: 'User' });
        await user.save();
        return res.json({ insertedId: user._id });
    } catch (err) {
        console.error('Error storing user:', err);
        return res.status(500).json({ error: 'Error storing user' });
    }
});

/**
 * GET /users/me
 * The profile of the currently authenticated caller.
 */
router.get('/users/me', requireAuth, async (req, res) => {
    try {
        return res.json(req.user);
    } catch (err) {
        console.error('Error fetching user:', err);
        return res.status(500).json({ error: 'Error fetching user' });
    }
});

/**
 * PUT /users/admin
 * Promotes a user to Admin. Admin only - the role is read from MongoDB.
 */
router.put('/users/admin', requireAdmin, writeLimiter, makeAdminValidation, handleValidation, async (req, res) => {
    const { email } = req.body;
    try {
        if (email === normalizeEmail(req.user.email)) {
            return res.status(400).json({ error: 'Cannot modify your own admin status' });
        }
        const user = await findUserByEmail(email);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.role === 'Admin') {
            return res.status(400).json({ error: 'User is already an admin' });
        }
        const result = await User.updateOne({ _id: user._id }, { $set: { role: 'Admin' } });
        console.log(`Updated user ${email} to admin, modified: ${result.modifiedCount}`);
        return res.json({ modifiedCount: result.modifiedCount });
    } catch (err) {
        console.error('Error making admin:', err);
        return res.status(500).json({ error: 'Error making admin' });
    }
});

/**
 * GET /users/:email
 * Returns the role/name of a user. Restricted to the caller themselves or an
 * administrator so that the endpoint cannot be used to enumerate accounts.
 */
router.get('/users/:email', requireOwnerOrAdmin, async (req, res) => {
    try {
        const requested = normalizeEmail(req.params.email);
        if (!req.isAdmin && requested !== normalizeEmail(req.user.email)) {
            return res.status(403).json({ error: 'Unauthorized to access this user' });
        }
        const user = await findUserByEmail(requested);
        if (!user) {
            return res.status(404).json({ error: 'User not found', name: null, admin: false });
        }
        return res.json({ admin: user.role === 'Admin', name: user.name });
    } catch (err) {
        console.error('Error checking user:', err);
        return res.status(500).json({ error: 'Error checking user' });
    }
});

module.exports = router;
