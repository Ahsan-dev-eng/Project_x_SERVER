const { extractBearerToken, resolveAuthenticatedUser } = require('./firebase');

/**
 * Shared credential resolution for the protected route guards.
 * Returns either `{ user, source, claims }` or `null`.
 */
const resolveRequestUser = async (req) => {
    const token = extractBearerToken(req);
    if (!token) return null;
    return resolveAuthenticatedUser(token);
};

/**
 * Requires a valid Firebase ID token or legacy session JWT.
 * Responds 401 when no valid token is present.
 */
const requireAuth = async (req, res, next) => {
    try {
        const resolved = await resolveRequestUser(req);
        if (!resolved) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        req.user = resolved.user;
        req.auth = { source: resolved.source, claims: resolved.claims };
        return next();
    } catch (err) {
        console.error('Error verifying user:', err.name, err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

/**
 * Requires a valid token AND the `Admin` role.
 *
 * The role is read exclusively from the MongoDB `usersInfo` collection. A
 * client supplied flag (for example the `admin` field returned by POST /login)
 * is never trusted - it is only ever used for UI affordances.
 *
 * Responds 401 when the token is missing/invalid and 403 when the caller is
 * authenticated but is not an administrator.
 */
const requireAdmin = async (req, res, next) => {
    try {
        const resolved = await resolveRequestUser(req);
        if (!resolved) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        if (resolved.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Unauthorized: Admin access required' });
        }
        req.user = resolved.user;
        req.auth = { source: resolved.source, claims: resolved.claims };
        return next();
    } catch (err) {
        console.error('Error verifying admin:', err.name, err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

/**
 * Allows the resource owner OR an administrator through.
 * Used by routes such as GET /orders/:id and DELETE /appointments/:id.
 */
const requireOwnerOrAdmin = async (req, res, next) => {
    try {
        const resolved = await resolveRequestUser(req);
        if (!resolved) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        req.user = resolved.user;
        req.auth = { source: resolved.source, claims: resolved.claims };
        req.isAdmin = resolved.user.role === 'Admin';
        return next();
    } catch (err) {
        console.error('Error verifying user:', err.name, err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

module.exports = { requireAuth, requireAdmin, requireOwnerOrAdmin };
