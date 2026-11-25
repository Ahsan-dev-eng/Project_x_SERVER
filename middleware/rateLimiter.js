const rateLimit = require('express-rate-limit');

/**
 * Builds a rate limiter that always answers with a clean `{ error }` JSON body
 * so the frontend `getApiErrorMessage()` helper can display it directly.
 */
const createLimiter = ({ windowMs, limit, message }) => rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: message },
});

/** Login / registration - brute force protection. */
const authLimiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    message: 'Too many authentication attempts. Please try again later.',
});

/** Order creation and status changes. */
const orderLimiter = createLimiter({
    windowMs: 60 * 1000,
    limit: 30,
    message: 'Too many order requests. Please try again shortly.',
});

/** Appointment booking, rescheduling and payment. */
const bookingLimiter = createLimiter({
    windowMs: 60 * 1000,
    limit: 20,
    message: 'Too many booking requests. Please try again shortly.',
});

/** Payment attempts. */
const paymentLimiter = createLimiter({
    windowMs: 60 * 1000,
    limit: 20,
    message: 'Too many payment requests. Please try again shortly.',
});

/** Public review submissions. */
const reviewLimiter = createLimiter({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    message: 'Too many reviews submitted. Please try again later.',
});

/** Generic guard for every other write endpoint. */
const writeLimiter = createLimiter({
    windowMs: 60 * 1000,
    limit: 120,
    message: 'Too many requests. Please try again shortly.',
});

module.exports = {
    authLimiter,
    orderLimiter,
    bookingLimiter,
    paymentLimiter,
    reviewLimiter,
    writeLimiter,
};
