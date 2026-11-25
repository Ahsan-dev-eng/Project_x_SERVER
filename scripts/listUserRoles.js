/**
 * Lists the users in the backend database together with their roles, so the
 * admin bootstrap can be confirmed.
 *
 * Run with:  node scripts/listUserRoles.js
 */
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env.local') });
dotenv.config();

const { User } = require(path.join(__dirname, '..', 'models'));

(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    const users = await User.find({}, 'email name role firebaseUid').sort({ email: 1 }).lean();

    console.log(`USERS: ${users.length}`);
    console.log('='.repeat(72));
    users.forEach((u) => {
        const role = u.role === 'Admin' ? 'Admin' : 'User ';
        const linked = u.firebaseUid ? `firebaseUid:${u.firebaseUid}` : '(not linked to Firebase yet)';
        console.log(`${role}  ${u.email}  ${linked}`);
    });

    const admins = users.filter((u) => u.role === 'Admin');
    console.log('='.repeat(72));
    console.log(`ADMINS: ${admins.length}`);
    if (!admins.length) {
        console.log('❌ No admin account found. Bootstrap one with:');
        console.log('   db.usersInfo.updateOne({ email: "<you@example.com>" }, { $set: { role: "Admin" } })');
    } else {
        admins.forEach((a) => console.log(`✅ ${a.email}`));
    }

    await mongoose.disconnect();
    process.exit(admins.length ? 0 : 1);
})().catch((err) => {
    console.error(err);
    process.exit(1);
});
