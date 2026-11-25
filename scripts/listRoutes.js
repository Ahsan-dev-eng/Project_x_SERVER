/**
 * Prints every route the Express app has registered.
 *
 * Run with:  npm run routes
 */
const path = require('path');
const mongoose = require('mongoose');

const root = path.join(__dirname, '..');
const app = require(path.join(root, 'index'));

const list = [];

const collect = (stack, prefix = '') => {
    stack.forEach((layer) => {
        if (layer.route) {
            const methods = Object.keys(layer.route.methods)
                .filter((m) => layer.route.methods[m])
                .map((m) => m.toUpperCase())
                .join(',');
            list.push(`${methods.padEnd(14)} ${prefix}${layer.route.path}`);
        } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
            collect(layer.handle.stack, prefix);
        }
    });
};

collect(app.router.stack);

const sorted = list.sort();
const counts = new Map();
sorted.forEach((entry) => counts.set(entry, (counts.get(entry) || 0) + 1));

console.log(`TOTAL ROUTES: ${sorted.length}\n`);
sorted.forEach((entry) => console.log(entry));

const duplicates = [...counts.entries()].filter(([, n]) => n > 1);
console.log(`\nDUPLICATE ROUTE DEFINITIONS: ${duplicates.length}`);
duplicates.forEach(([entry, n]) => console.log(`  x${n}  ${entry}`));

mongoose.disconnect().then(() => process.exit(duplicates.length ? 1 : 0));
