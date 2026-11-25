/**
 * Verifies that every route in the frontend contract
 * (my-app/src/services/endpoints.js) exists in the backend.
 *
 * Run with:  npm run verify
 *
 * Set FRONTEND_ENDPOINTS to point at a different endpoints.js if the frontend
 * lives somewhere else.
 */
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

const root = path.join(__dirname, '..');
const app = require(path.join(root, 'index'));

const FRONTEND_ENDPOINTS = process.env.FRONTEND_ENDPOINTS
    || 'F:\\Project\\my-app\\src\\services\\endpoints.js';

if (!fs.existsSync(FRONTEND_ENDPOINTS)) {
    console.error(`❌ Frontend contract not found: ${FRONTEND_ENDPOINTS}`);
    console.error('   Set FRONTEND_ENDPOINTS to the absolute path of src/services/endpoints.js');
    process.exit(1);
}

// --- Collect the backend routes -------------------------------------------
const backend = new Set();
const backendRaw = [];
const collect = (stack) => {
    stack.forEach((layer) => {
        if (layer.route) {
            Object.keys(layer.route.methods)
                .filter((m) => layer.route.methods[m])
                .forEach((m) => {
                    backendRaw.push(`${m.toUpperCase()} ${layer.route.path}`);
                    backend.add(`${m.toUpperCase()} ${layer.route.path.replace(/:[^/]+/g, ':p')}`);
                });
        } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
            collect(layer.handle.stack);
        }
    });
};
collect(app.router.stack);

// --- Parse the frontend contract ------------------------------------------
const source = fs.readFileSync(FRONTEND_ENDPOINTS, 'utf8');
const frontend = [];

// key: 'value'  ->  literal path
source.replace(/^\s*(\w+):\s*'([^']+)'/gm, (_, key, value) => {
    frontend.push({ key, path: value });
    return _;
});

// key: (arg) => `/path/${arg}/tail`
source.replace(/^\s*(\w+):\s*\([^)]*\)\s*=>\s*`([^`]+)`/gm, (_, key, value) => {
    frontend.push({ key, path: value });
    return _;
});

/**
 * Converts a frontend template (`/orders/${id}`) into an Express pattern.
 * Express matches on path SHAPE, not on the parameter name, so every
 * parameter is normalised to `:p` before comparing.
 */
const toExpressPattern = (template) => template.replace(/\$\{[^}]+\}/g, ':p');

/** Normalises a registered Express path (`/orders/:id`) to the same shape. */
const toShape = (routePath) => routePath.replace(/:[^/]+/g, ':p');

const CANDIDATE_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

const lines = [];
let missing = 0;
let matched = 0;

lines.push('FRONTEND CONTRACT -> BACKEND ROUTE CHECK');
lines.push('='.repeat(72));

frontend.forEach(({ key, path: template }) => {
    const pattern = toExpressPattern(template);
    const candidates = CANDIDATE_METHODS.filter((m) => backend.has(`${m} ${pattern}`));

    if (candidates.length) {
        matched += 1;
        lines.push(`✅ ${key.padEnd(24)} ${template.padEnd(42)} -> ${candidates.join(', ')}`);
    } else {
        missing += 1;
        lines.push(`❌ ${key.padEnd(24)} ${template.padEnd(42)} -> NO BACKEND ROUTE (${pattern})`);
    }
});

lines.push('='.repeat(72));
lines.push(`Frontend endpoints: ${frontend.length}   Matched: ${matched}   Missing: ${missing}`);
lines.push('');
lines.push(`Backend routes registered: ${backendRaw.length}`);
lines.push('');
lines.push('BACKEND ROUTES WITHOUT A FRONTEND ENDPOINT (extra/alias):');
const frontendShapes = new Set(frontend.map((f) => toShape(toExpressPattern(f.path))));
[...backendRaw].sort().forEach((route) => {
    const routePath = route.split(' ').slice(1).join(' ');
    if (!frontendShapes.has(toShape(routePath))) {
        lines.push(`   ${route}`);
    }
});

console.log(lines.join('\n'));
mongoose.disconnect().then(() => process.exit(missing ? 1 : 0));
