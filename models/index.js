const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    name: { type: String, required: true, trim: true },
    // Server-side role. This is the ONLY source of truth for admin privileges -
    // it is never derived from a client supplied flag.
    role: { type: String, default: 'User' },
    // Optional link to the Firebase Auth uid, populated on first token verification.
    firebaseUid: { type: String, default: null },
});

const orderSchema = new mongoose.Schema({
    email: { type: String, required: true },
    name: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    address: { type: String, required: true },
    items: [{
        productId: { type: String, required: true },
        medicineName: { type: String, required: true }, // Changed to medicineName to match frontend
        quantity: { type: Number, required: true, min: 1 },
        price: { type: Number, required: true, min: 0 },
    }],
    total_price: { type: Number, required: true, min: 0 },
    status: { type: String, default: 'Pending' },
    order_date: { type: Date, default: Date.now },
});
const medicineSchema = new mongoose.Schema({
    medicine_name: { type: String, required: true },
    image_url: { type: String },
    price: { type: Number, required: true },
    composition: { type: String },
    uses: { type: String },
    side_effects: { type: String },
    manufacturer: { type: String },
    category: { type: String },
    excellent_review_percent: { type: Number, default: 0 },
    top_rated: { type: Boolean, default: false },
});

const doctorSchema = new mongoose.Schema({
    name: { type: String, required: true },
    image: { type: String },
    qualifications: { type: String },
    specializations: { type: String },
    availability: { type: [String], default: [] },
    department: { type: String },
    experience: { type: Number },
    contact: { type: String },
    hospital: { type: String },
    consultation_fee: { type: Number, required: true },
    location: { type: String },
    rating: { type: Number, default: 0 },
    top_rated: { type: Boolean, default: false },
});

const appointmentSchema = new mongoose.Schema({
    userEmail: String,
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
    date: Date,
    time: String,
    status: { type: String, default: 'Pending' },
});


const articleSchema = new mongoose.Schema({
    title: { type: String, required: true },
    authors: { type: [String], required: true },
    publication_year: { type: Number, required: true },
    published_date: { type: Date, required: true },
    journal: { type: String, required: true },
    category: { type: String, required: true },
    abstract: { type: String, required: true },
    doi: { type: String, required: true },
    url: { type: String, required: true },
    image_url: { type: String },
});

const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    feedback: { type: String, required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    date: { type: Date, default: Date.now },
});

const cartSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    items: [{
        productId: { type: String, required: true },
        medicineName: { type: String, required: true }, // Updated for consistency
        price: { type: Number, required: true },
        image_url: { type: String },
        quantity: { type: Number, required: true, min: 1 },
    }],
});

const User = mongoose.model('User', userSchema, 'usersInfo');
const Order = mongoose.model('Order', orderSchema, 'ordersInfo');
const Medicine = mongoose.model('Medicine', medicineSchema, 'medicine_info');
const Doctor = mongoose.model('Doctor', doctorSchema, 'doctor_info');
const Appointment = mongoose.model('Appointment', appointmentSchema, 'appointments');
const Article = mongoose.model('Article', articleSchema, 'articles');
const Review = mongoose.model('Review', reviewSchema, 'reviews');
const Cart = mongoose.model('Cart', cartSchema, 'carts');

/**
 * Normalises an email address so lookups are consistent regardless of the
 * casing used by the client or by Firebase.
 */
const normalizeEmail = (email) => (typeof email === 'string' ? email.trim().toLowerCase() : email);

/**
 * Case insensitive user lookup. Existing rows were written before the schema
 * lowercased emails, so a strict equality query could miss them.
 */
const findUserByEmail = (email) => {
    if (typeof email !== 'string' || !email.trim()) return null;
    const escaped = email.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return User.findOne({ email: new RegExp(`^${escaped}$`, 'i') });
};

module.exports = {
    User,
    Order,
    Medicine,
    Doctor,
    Appointment,
    Article,
    Review,
    Cart,
    normalizeEmail,
    findUserByEmail,
};
