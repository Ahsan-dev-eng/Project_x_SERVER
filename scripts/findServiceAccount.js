/**
 * Locates a Firebase service account key file on this machine.
 *
 * Scans candidate folders for JSON files whose contents look like a Firebase
 * service account ("type": "service_account"). The private key is never
 * printed - only the file path and the non-secret metadata.
 */
const fs = require('fs');
const path = require('path');

const ROOTS = [
    'F:\\Project',
    path.join(process.env.USERPROFILE || '', 'Downloads'),
    path.join(process.env.USERPROFILE || '', 'Desktop'),
    path.join(process.env.USERPROFILE || '', 'Documents'),
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'build', 'dist', '.next', 'coverage']);

const MAX_DEPTH = 5;

const looksLikeServiceAccount = (filePath) => {
    try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile() || stat.size > 200 * 1024) return false;
        if (!filePath.toLowerCase().endsWith('.json')) return false;
        const content = fs.readFileSync(filePath, 'utf8');
        if (!content.includes('service_account')) return false;
        const parsed = JSON.parse(content);
        return parsed.type === 'service_account' && !!parsed.private_key;
    } catch {
        return false;
    }
};

const found = [];

const walk = (dir, depth) => {
    if (depth > MAX_DEPTH) return;
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return;
    }
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            walk(full, depth + 1);
        } else if (looksLikeServiceAccount(full)) {
            found.push(full);
        }
    }
};

ROOTS.filter(Boolean).forEach((root) => {
    if (fs.existsSync(root)) walk(root, 0);
});

console.log(`SEARCHED: ${ROOTS.filter((r) => r && fs.existsSync(r)).join(', ')}`);
console.log(`SERVICE ACCOUNT FILES FOUND: ${found.length}`);
found.forEach((file) => {
    const key = JSON.parse(fs.readFileSync(file, 'utf8'));
    console.log(`\n  path        : ${file}`);
    console.log(`  project_id  : ${key.project_id}`);
    console.log(`  client_email: ${key.client_email}`);
    console.log(`  private_key : present`);
});
if (!found.length) {
    console.log('\nNo Firebase service account key file was found in the searched folders.');
}
