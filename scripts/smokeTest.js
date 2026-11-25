/**
 * Smoke verification for the MediMart backend.
 *
 * Run with:  npm test
 *
 * It boots the real Express app on a throwaway port and verifies that:
 *   - public catalogue routes answer 200
 *   - protected routes answer 401 without a token (and with a bad token)
 *   - admin-only routes answer 403 for a non-admin user
 *   - admin-only routes answer 200 for an admin user
 *   - validation failures answer 400 with a clean `{ error }` body
 *   - unmatched routes answer 404 with a clean `{ error }` body
 *
 * Temporary users are created for the run and removed again in the cleanup step.
 */
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = require('../index');
const { User } = require('../models');
const { getJwtSecret, isFirebaseReady } = require('../middleware/firebase');

const TEST_PORT = 3999;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const stamp = Date.now();
const USER_EMAIL = `smoke-test-user-${stamp}@example.com`;
const ADMIN_EMAIL = `smoke-test-admin-${stamp}@example.com`;

const results = [];
let server;

const check = (name, expected, actual, extra = '') => {
    const passed = expected === actual;
    results.push({ name, expected, actual, passed });
    console.log(`${passed ? '✅' : '❌'} ${name} - expected ${expected}, got ${actual}${extra ? ` ${extra}` : ''}`);
};

const request = async (method, path, { token, body } = {}) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    const res = await fetch(`${BASE_URL}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
    });

    let data = null;
    const text = await res.text();
    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = text;
    }
    return { status: res.status, data };
};

const runPublicChecks = async () => {
    console.log('🧪 MediMart backend smoke test\n');

    // --- Create the temporary test users -------------------------------
    await User.create({ email: USER_EMAIL, name: 'Smoke Test User', role: 'User' });
    await User.create({ email: ADMIN_EMAIL, name: 'Smoke Test Admin', role: 'Admin' });

    const userToken = jwt.sign({ email: USER_EMAIL }, getJwtSecret(), { expiresIn: '1h' });
    const adminToken = jwt.sign({ email: ADMIN_EMAIL }, getJwtSecret(), { expiresIn: '1h' });

    // --- Public routes --------------------------------------------------
    let res = await request('GET', '/medicine_info');
    check('GET /medicine_info (public)', 200, res.status);

    res = await request('GET', '/doctor_info');
    check('GET /doctor_info (public)', 200, res.status);

    res = await request('GET', '/reviews');
    check('GET /reviews (public)', 200, res.status);

    res = await request('GET', '/categories');
    check('GET /categories (public)', 200, res.status);

    res = await request('GET', '/medicine_info?search=para&page=1&limit=5');
    check('GET /medicine_info with query params', 200, res.status);

    // --- Protected routes without a token ------------------------------
    res = await request('GET', '/users/me');
    check('GET /users/me without token', 401, res.status);
    check('  ...returns a clean { error } body', true, typeof res.data?.error === 'string', JSON.stringify(res.data));

    res = await request('POST', '/orders', { body: {} });
    check('POST /orders without token', 401, res.status);

    res = await request('GET', '/cart');
    check('GET /cart without token', 401, res.status);

    res = await request('POST', '/appointments', { body: {} });
    check('POST /appointments without token', 401, res.status);

    res = await request('GET', '/users/me', { token: 'not-a-real-token' });
    check('GET /users/me with an invalid token', 401, res.status);

    return { userToken, adminToken };
};

const runAdminChecks = async (userToken, adminToken) => {
    // --- Admin routes with a non-admin token -> 403 ---------------------
    let res = await request('GET', '/orders', { token: userToken });
    check('GET /orders with a non-admin token', 403, res.status);

    res = await request('GET', '/stats/revenue', { token: userToken });
    check('GET /stats/revenue with a non-admin token', 403, res.status);

    res = await request('GET', '/appointments', { token: userToken });
    check('GET /appointments with a non-admin token', 403, res.status);

    res = await request('POST', '/medicine_info', { token: userToken, body: { medicine_name: 'x', price: 1 } });
    check('POST /medicine_info with a non-admin token', 403, res.status);

    res = await request('PUT', '/users/admin', { token: userToken, body: { email: ADMIN_EMAIL } });
    check('PUT /users/admin with a non-admin token', 403, res.status);

    res = await request('DELETE', '/medicine_info/507f1f77bcf86cd799439011', { token: userToken });
    check('DELETE /medicine_info/:id with a non-admin token', 403, res.status);

    // --- Admin routes with an admin token -> 200 ------------------------
    res = await request('GET', '/orders', { token: adminToken });
    check('GET /orders with an admin token', 200, res.status);

    res = await request('GET', '/stats/revenue', { token: adminToken });
    check('GET /stats/revenue with an admin token', 200, res.status);

    res = await request('GET', '/appointments', { token: adminToken });
    check('GET /appointments with an admin token', 200, res.status);

    res = await request('GET', '/users/me', { token: adminToken });
    check('GET /users/me with an admin token', 200, res.status);
    check('  ...resolves the MongoDB role', 'Admin', res.data?.role);

    // --- Owner scoped routes -------------------------------------------
    res = await request('GET', `/orders/${USER_EMAIL}`, { token: userToken });
    check('GET /orders/:email as the owner', 200, res.status);

    res = await request('GET', `/orders/${ADMIN_EMAIL}`, { token: userToken });
    check('GET /orders/:email for another user', 403, res.status);

    res = await request('GET', `/appointments/${USER_EMAIL}`, { token: userToken });
    check('GET /appointments/:userEmail as the owner', 200, res.status);

    // --- ObjectId routes do not collide with the email routes -----------
    const fakeObjectId = '507f1f77bcf86cd799439011';
    res = await request('GET', `/appointments/${fakeObjectId}`, { token: userToken });
    check('GET /appointments/:id resolves the ObjectId route', 404, res.status, JSON.stringify(res.data));

    res = await request('GET', `/orders/${fakeObjectId}`, { token: userToken });
    check('GET /orders/:id resolves the ObjectId route', 404, res.status, JSON.stringify(res.data));

    // --- Validation ------------------------------------------------------
    res = await request('POST', '/reviews', { body: { name: 'A', email: 'not-an-email', feedback: 'short', rating: 9 } });
    check('POST /reviews with an invalid body', 400, res.status);
    check('  ...returns a clean { error } body', true, typeof res.data?.error === 'string', JSON.stringify(res.data));

    res = await request('POST', '/orders', { token: userToken, body: { email: USER_EMAIL } });
    check('POST /orders with an invalid body', 400, res.status);

    res = await request('POST', '/appointments', { token: userToken, body: { doctorId: 'nope', userEmail: USER_EMAIL, date: 'x', time: '99' } });
    check('POST /appointments with an invalid body', 400, res.status);

    res = await request('POST', '/login', { body: { email: USER_EMAIL, firebaseToken: 'bogus' } });
    // When the Firebase Admin SDK has no credentials the endpoint fails closed
    // with 503; once a service account key is present an invalid token is 401.
    check(
        'POST /login rejects an invalid Firebase token',
        isFirebaseReady() ? 401 : 503,
        res.status,
        `(${isFirebaseReady() ? 'Admin SDK configured' : 'Admin SDK not configured'})`
    );

    // --- Unknown route ----------------------------------------------------
    res = await request('GET', '/definitely-not-a-real-route');
    check('GET /definitely-not-a-real-route', 404, res.status);
    check('  ...returns a clean { error } body', true, typeof res.data?.error === 'string', JSON.stringify(res.data));
};

const cleanup = async () => {
    try {
        await User.deleteMany({ email: { $in: [USER_EMAIL, ADMIN_EMAIL] } });
    } catch (err) {
        console.error('Cleanup failed:', err.message);
    }
};

const main = async () => {
    try {
        await mongoose.connection.asPromise();
        const { userToken, adminToken } = await runPublicChecks();
        await runAdminChecks(userToken, adminToken);
    } catch (err) {
        console.error('\n💥 Smoke test crashed:', err);
        results.push({ name: 'Smoke test execution', expected: 'no crash', actual: err.message, passed: false });
    } finally {
        await cleanup();
        if (server) await new Promise((resolve) => server.close(resolve));
        await mongoose.disconnect();
    }

    const failed = results.filter((r) => !r.passed);
    console.log(`\n${'-'.repeat(60)}`);
    console.log(`Total: ${results.length}  Passed: ${results.length - failed.length}  Failed: ${failed.length}`);
    if (failed.length) {
        console.log('\n❌ Failed checks:');
        failed.forEach((f) => console.log(`   - ${f.name} (expected ${f.expected}, got ${f.actual})`));
    } else {
        console.log('\n✅ All smoke checks passed.');
    }
    process.exit(failed.length ? 1 : 0);
};

server = app.listen(TEST_PORT, () => {
    console.log(`Smoke test server listening on ${BASE_URL}\n`);
    main();
});
