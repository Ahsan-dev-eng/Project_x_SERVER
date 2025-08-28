const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config({ path: '.env.local' });
const { GoogleGenerativeAI } = require('@google/generative-ai');
const app = express();
const port = 3001;

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Log requests
app.use((req, res, next) => {
    console.log(`Request: ${req.method} ${req.url}`);
    next();
});
// MongoDB connection
const uri = process.env.MONGODB_URI;
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// Schemas
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    role: { type: String, default: 'User' },
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

// Gemini AI setup
console.log('Gemini API Key:', process.env.API_KEY);
if (!process.env.API_KEY) {
    console.error('Error: GEMINI_API_KEY is not defined in .env.local');
    process.exit(1);
}
const genAI = new GoogleGenerativeAI(process.env.API_KEY);

// Middleware for admin authorization using JWT
const requireAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mysecretkey');
        const user = await User.findOne({ email: decoded.email });
        if (!user || user.role !== 'Admin') {
            return res.status(403).json({ error: 'Unauthorized: Admin access required' });
        }
        req.user = user;
        next();
    } catch (err) {
        console.error('Error verifying admin:', err.name, err.message);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Middleware for user authorization using JWT
const requireAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Authorization token required' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mysecretkey');
        const user = await User.findOne({ email: decoded.email });
        if (!user) {
            return res.status(403).json({ error: 'User not found' });
        }
        req.user = user;
        next();
    } catch (err) {
        console.error('Error verifying user:', err.name, err.message);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Login endpoint to generate JWT after Firebase verification
app.post('/login', async (req, res) => {
    const { email, firebaseToken } = req.body;
    if (!email || !firebaseToken) {
        return res.status(400).json({ error: 'Email and Firebase token are required' });
    }
    try {
        // Verify Firebase token (simplified; in production, verify with Firebase Admin SDK)
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const token = jwt.sign({ email }, process.env.JWT_SECRET || 'mysecretkey', { expiresIn: '1h' });
        res.json({ token, admin: user.role === 'Admin' });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Store User Route
app.post('/users', async (req, res) => {
    const { email, name, role = 'User' } = req.body;
    if (!email || !name) {
        return res.status(400).json({ error: 'Email and name are required' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        const user = new User({ email, name, role });
        await user.save();
        res.json({ insertedId: user._id });
    } catch (err) {
        console.error('Error storing user:', err);
        res.status(500).json({ error: 'Error storing user' });
    }
});

// User profile endpoint
app.get('/users/me', requireAuth, async (req, res) => {
    try {
        res.json(req.user);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ error: 'Error fetching user' });
    }
});



// New Route: Fetch unique specializations
app.get('/doctor_info/specializations', async (req, res) => {
    try {
        const specializations = await Doctor.distinct('specializations');
        console.log(`Fetched ${specializations.length} unique specializations`);
        res.json(specializations);
    } catch (err) {
        console.error('Error fetching specializations:', err);
        res.status(500).json({ error: 'Error fetching specializations' });
    }
});

// Dashboard Stats Routes
app.get('/stats/revenue', requireAdmin, async (req, res) => {
    try {
        const result = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $group: { _id: null, revenue: { $sum: '$total_price' } } },
        ]);
        const revenue = result.length > 0 ? result[0].revenue : 0;
        res.json({ revenue });
    } catch (err) {
        console.error('Error fetching revenue:', err);
        res.status(500).json({ error: 'Error fetching revenue' });
    }
});

app.get('/stats/total-sales', requireAdmin, async (req, res) => {
    try {
        const result = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $unwind: '$items' },
            { $group: { _id: null, totalSales: { $sum: '$items.quantity' } } },
        ]);
        const totalSales = result.length > 0 ? result[0].totalSales : 0;
        res.json({ totalSales });
    } catch (err) {
        console.error('Error fetching total sales:', err);
        res.status(500).json({ error: 'Error fetching total sales' });
    }
});

app.get('/stats/top-products', requireAdmin, async (req, res) => {
    try {
        const topProducts = await Order.aggregate([
            { $match: { status: 'Paid' } },
            { $unwind: '$items' },
            {
                $group: {
                    _id: '$items.medicineName',
                    totalQuantity: { $sum: '$items.quantity' },
                    price: { $first: '$items.price' },
                },
            },
            { $sort: { totalQuantity: -1 } },
            { $limit: 5 },
            {
                $project: {
                    _id: 0,
                    medicineName: '$_id',
                    totalQuantity: 1,
                    price: 1,
                },
            },
        ]);
        res.json(topProducts);
    } catch (err) {
        console.error('Error fetching top products:', err);
        res.status(500).json({ error: 'Error fetching top products' });
    }
});

app.get('/stats/total-users', requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        res.json({ totalUsers });
    } catch (err) {
        console.error('Error fetching total users:', err);
        res.status(500).json({ error: 'Error fetching total users' });
    }
});

// Chatbot Endpoint
app.post('/chat', async (req, res) => {
    try {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }

        const systemPrompt = `
You are MediBot, a healthcare assistant for MediMart, an online medicine e-commerce store.

Core Rules:

Only respond to queries related to healthcare, medicine, symptoms, treatments, or MediMart products.

If the query is not related to healthcare or medicine, reply exactly with:
"Sorry, I can only help with healthcare and medicine related queries."

For symptoms, suggest possible common causes and over-the-counter medicines available at MediMart. Always include the disclaimer:
"This is not medical advice. Please consult a doctor for proper diagnosis and treatment."

If suggesting medicines, only mention common OTC options (e.g., Paracetamol for fever/pain, Antacids for indigestion, Cough Syrup for mild cough, Antihistamines for allergies). Suggest users to search our store (MediMart) for these products.

Keep responses concise, helpful, and professional.

Do not provide medical diagnoses or prescribe medications.

Style & Tone Enhancements:

Be effective → deliver clear, practical answers.

Be efficient → keep responses short, direct, and easy to follow.

Be user-friendly → use simple, everyday language that anyone can understand.

Be sentimental → show empathy and care (acknowledge discomfort, reassure the user).

Be knowledgeable → provide trustworthy, reliable, and commonly known healthcare information.
User query: ${message}
`;

        let model;
        try {
            model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
            const result = await model.generateContent(systemPrompt);
            const response = result.response.text();
            res.json({ reply: response });
        } catch (modelErr) {
            console.warn('Primary model (gemini-1.5-flash) failed:', modelErr.message);
            try {
                model = genAI.getGenerativeModel({ model: "gemini-pro" });
                const result = await model.generateContent(systemPrompt);
                const response = result.response.text();
                res.json({ reply: response });
            } catch (fallbackErr) {
                throw fallbackErr;
            }
        }
    } catch (err) {
        console.error('Error in chatbot:', {
            message: err.message,
            stack: err.stack,
            status: err.response?.status,
            data: err.response?.data,
        });
        if (err.response && err.response.status === 401) {
            res.status(401).json({ error: 'Invalid API key. Please contact support.' });
        } else if (err.response && err.response.status === 400 && err.message.includes('API_KEY_INVALID')) {
            res.status(400).json({ error: 'Invalid API key. Please check the API key configuration.' });
        } else if (err.response && err.response.status === 429) {
            res.status(429).json({ error: 'Rate limit exceeded. Please try again later.' });
        } else if (err.message.includes('model')) {
            res.status(400).json({ error: 'Invalid or unavailable model specified. Please try again later.' });
        } else {
            res.status(500).json({ error: 'Error generating response. Please try again.' });
        }
    }
});

// Doctor Routes
app.get('/doctor_info', async (req, res) => {
    try {
        const {
            search = '',
            minPrice = 0,
            maxPrice = Number.MAX_SAFE_INTEGER,
            minRating = 0,
            specializations = '',
            availability = '',
            sort = '',
            page = 1,
            limit = 6,
        } = req.query;

        const query = {};
        if (search) query.name = { $regex: search, $options: 'i' };
        if (minPrice || maxPrice !== Number.MAX_SAFE_INTEGER) {
            query.consultation_fee = { $gte: Number(minPrice), $lte: Number(maxPrice) };
        }
        if (minRating) query.rating = { $gte: Number(minRating) };
        if (specializations) query.specializations = { $regex: specializations, $options: 'i' };
        if (availability) query.availability = { $in: [availability] };

        let sortOption = {};
        if (sort === 'fee-asc') sortOption.consultation_fee = 1;
        else if (sort === 'fee-desc') sortOption.consultation_fee = -1;
        else if (sort === 'rating-desc') sortOption.rating = -1;

        const skip = (Number(page) - 1) * Number(limit);
        const doctors = await Doctor.find(query)
            .sort(sortOption)
            .skip(skip)
            .limit(Number(limit));
        const total = await Doctor.countDocuments(query);

        res.json({
            doctors,
            total,
            page: Number(page),
            pages: Math.ceil(total / Number(limit)),
        });
         
    } catch (err) {
        console.error('Error fetching doctors:', err);
        res.status(500).json({ error: 'Error fetching doctors' });
    }
});

app.get('/doctor_info/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const doctors = await Doctor.find({
            name: { $regex: q, $options: 'i' }
        });
        console.log(`Search results for "${q}":`, doctors.length);
        res.json(doctors);
    } catch (err) {
        console.error('Error searching doctors:', err);
        res.status(500).json({ error: 'Error searching doctors' });
    }
});

app.get('/doctor_info/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const doctor = await Doctor.findById(req.params.id);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Fetched doctor: ${doctor.name}`);
        res.json(doctor);
    } catch (err) {
        console.error('Error fetching doctor:', err);
        res.status(500).json({ error: 'Error fetching doctor' });
    }
});

app.put('/doctor_info/:id', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const updates = req.body;
        const allowedUpdates = [
            'name', 'image', 'qualifications', 'specializations', 'availability',
            'department', 'experience', 'contact', 'hospital', 'consultation_fee',
            'location', 'rating', 'top_rated'
        ];
        const isValidUpdate = Object.keys(updates).every(key => allowedUpdates.includes(key));
        if (!isValidUpdate) {
            return res.status(400).json({ error: 'Invalid updates' });
        }
        const doctor = await Doctor.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Updated doctor: ${doctor.name}`);
        res.json(doctor);
    } catch (err) {
        console.error('Error updating doctor:', err);
        res.status(500).json({ error: 'Error updating doctor' });
    }
});

app.patch('/doctor_info/:id/top-rated', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const doctor = await Doctor.findById(req.params.id);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        const newStatus = !doctor.top_rated;
        const updatedDoctor = await Doctor.findByIdAndUpdate(
            req.params.id,
            { top_rated: newStatus },
            { new: true }
        );
        console.log(`Toggled top_rated for ${doctor.name} to ${newStatus}`);
        res.json({ top_rated: updatedDoctor.top_rated });
    } catch (err) {
        console.error('Error updating top-rated status:', err);
        res.status(500).json({ error: 'Error updating top-rated status' });
    }
});

app.delete('/doctor_info/:id', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const result = await Doctor.deleteOne({ _id: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Deleted doctor ID: ${req.params.id}`);
        res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting doctor:', err);
        res.status(500).json({ error: 'Error deleting doctor' });
    }
});

// Appointment Routes
app.post('/appointments', async (req, res) => {
    try {
        const { doctorId, userEmail, date, time } = req.body;
        if (!mongoose.Types.ObjectId.isValid(doctorId)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        if (!doctorId || !userEmail || !date || !time) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        const doctor = await Doctor.findById(doctorId);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        // Check for existing appointment with same doctor, date, and time
        const existingAppointment = await Appointment.findOne({
            doctorId,
            date: new Date(date),
            time
        });
        if (existingAppointment) {
            return res.status(400).json({ error: 'This time slot is already booked. Please choose another time.' });
        }
        const appointment = new Appointment({ doctorId, userEmail, date, time });
        await appointment.save();
        console.log(`Created appointment for doctor ID: ${doctorId}, user: ${userEmail}`);
        res.json({ insertedId: appointment._id });
    } catch (err) {
        console.error('Error creating appointment:', err);
        res.status(500).json({ error: 'Error creating appointment' });
    }
});

app.get('/appointments', requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const skip = (Number(page) - 1) * Number(limit);
        const appointments = await Appointment.find()
            .skip(skip)
            .limit(Number(limit))
            .lean();
        const total = await Appointment.countDocuments();
        res.json({
            appointments,
            total,
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching appointments:', err);
        res.status(500).json({ error: 'Error fetching appointments' });
    }
});

app.get('/appointments/:userEmail', async (req, res) => {
    try {
        const appointments = await Appointment.find({ userEmail: req.params.userEmail })
            .populate('doctorId', 'name consultation_fee');
        console.log(`Fetched ${appointments.length} appointments for ${req.params.userEmail}`);
        res.json(appointments);
    } catch (err) {
        console.error('Error fetching appointments:', err);
        res.status(500).json({ error: 'Error fetching appointments' });
    }
});

// GET doctor availability
app.get('/doctors/:doctorId/availability', async (req, res) => {
    try {
        const doctorId = req.params.doctorId;
        const doctor = await Doctor.findById(doctorId);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }

        const { startDate } = req.query;
        const today = startDate ? new Date(startDate) : new Date();
        today.setHours(0, 0, 0, 0);

        // Use default working hours if not specified
        const workingHours = doctor.workingHours || { start: '09:00', end: '17:00' };
        const workingStartHour = parseInt(workingHours.start.split(':')[0]);
        const workingEndHour = parseInt(workingHours.end.split(':')[0]);

        const availability = [];
        const days = 30;

        for (let i = 0; i < days; i++) {
            const currentDate = new Date(today);
            currentDate.setDate(today.getDate() + i);

            // Skip weekends (optional, adjust based on requirements)
            if (currentDate.getDay() === 0 || currentDate.getDay() === 6) continue;

            // Get existing appointments for this date
            const startOfDay = new Date(currentDate);
            const endOfDay = new Date(currentDate);
            endOfDay.setDate(currentDate.getDate() + 1);

            const appointments = await Appointment.find({
                doctorId,
                date: { $gte: startOfDay, $lt: endOfDay },
            });

            // Generate available time slots
            const availableTimes = [];
            for (let hour = workingStartHour; hour < workingEndHour; hour++) {
                const time = `${hour.toString().padStart(2, '0')}:00`;
                if (!appointments.some(appt => appt.time === time)) {
                    availableTimes.push(time);
                }
            }

            if (availableTimes.length > 0) {
                availability.push({
                    date: currentDate.toISOString().split('T')[0],
                    times: availableTimes,
                });
            }
        }

        res.json({ availability });
    } catch (err) {
        console.error('Error fetching doctor availability:', err);
        res.status(500).json({ error: 'Error fetching availability' });
    }
});

app.put('/appointments/:id', async (req, res) => {
    try {
        const { date, time } = req.body;
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid appointment ID' });
        }
        if (!date || !time) {
            return res.status(400).json({ error: 'Date and time are required' });
        }
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        // Check for existing appointment with same doctor, date, and time
        const existingAppointment = await Appointment.findOne({
            doctorId: appointment.doctorId,
            date: new Date(date),
            time,
            _id: { $ne: req.params.id }, // Exclude the current appointment
        });
        if (existingAppointment) {
            return res.status(400).json({ error: 'This time slot is already booked. Please choose another time.' });
        }
        const updatedAppointment = await Appointment.findByIdAndUpdate(
            req.params.id,
            { date, time },
            { new: true, runValidators: true }
        );
        console.log(`Updated appointment ID: ${req.params.id} to date: ${date}, time: ${time}`);
        res.json({ modifiedCount: updatedAppointment ? 1 : 0 });
    } catch (err) {
        console.error('Error updating appointment:', err);
        res.status(500).json({ error: 'Error updating appointment' });
    }
});

// Pay Appointment Route
app.put('/appointments/:id/pay', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid appointment ID' });
        }
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        if (appointment.status === 'Paid') {
            return res.status(400).json({ error: 'Appointment already paid' });
        }
        const updatedAppointment = await Appointment.findByIdAndUpdate(
            req.params.id,
            { status: 'Paid' },
            { new: true }
        );
        console.log(`Marked appointment ID: ${req.params.id} as Paid`);
        res.json({ modifiedCount: updatedAppointment ? 1 : 0 });
    } catch (err) {
        console.error('Error paying for appointment:', err);
        res.status(500).json({ error: 'Error paying for appointment' });
    }
});

// Delete Appointment Route (for Cancel functionality)
app.delete('/appointment/:id', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid appointment ID' });
        }
        const result = await Appointment.deleteOne({ _id: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        console.log(`Deleted appointment ID: ${req.params.id}`);
        res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting appointment:', err);
        res.status(500).json({ error: 'Error deleting appointment' });
    }
});

// Medicine Routes
app.get('/medicine_info', async (req, res) => {
    try {
        const {
            search = '',
            minPrice = 0,
            maxPrice = Number.MAX_SAFE_INTEGER,
            minExcellentReview = 0,
            category = '',
            top_rated,
            sort = '',
            page = 1,
            limit = 12,
        } = req.query;

        const query = {};
        if (search) query.medicine_name = { $regex: search, $options: 'i' };
        if (minPrice || maxPrice !== Number.MAX_SAFE_INTEGER) {
            query.price = { $gte: Number(minPrice), $lte: Number(maxPrice) };
        }
        if (minExcellentReview) query.excellent_review_percent = { $gte: Number(minExcellentReview) };
        if (category) query.category = category;
        if (top_rated !== undefined) query.top_rated = top_rated === 'true';

        let sortOption = {};
        if (sort === 'price-asc') sortOption.price = 1;
        else if (sort === 'price-desc') sortOption.price = -1;
        else if (sort === 'review-desc') sortOption.excellent_review_percent = -1;

        const skip = (Number(page) - 1) * Number(limit);
        const medicines = await Medicine.find(query)
            .sort(sortOption)
            .skip(skip)
            .limit(Number(limit));
        const total = await Medicine.countDocuments(query);

        res.json({
            medicines,
            total,
            page: Number(page),
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching medicines:', err);
        res.status(500).json({ error: 'Error fetching medicines' });
    }
});

app.get('/medicine_info/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const medicines = await Medicine.find({
            medicine_name: { $regex: q, $options: 'i' }
        });
        console.log(`Search results for "${q}":`, medicines.length);
        res.json(medicines);
    } catch (err) {
        console.error('Error searching medicines:', err);
        res.status(500).json({ error: 'Error searching medicines' });
    }
});

app.get('/medicine_info/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid medicine ID' });
        }
        const medicine = await Medicine.findById(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        console.log(`Fetched medicine: ${medicine.medicine_name}`);
        res.json(medicine);
    } catch (err) {
        console.error('Error fetching medicine:', err);
        res.status(500).json({ error: 'Error fetching medicine' });
    }
});

app.patch('/medicine_info/:id/top-rated', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid medicine ID' });
        }
        const medicine = await Medicine.findById(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        const newStatus = !medicine.top_rated;
        const updatedMedicine = await Medicine.findByIdAndUpdate(
            req.params.id,
            { top_rated: newStatus },
            { new: true }
        );
        console.log(`Toggled top_rated for ${medicine.medicine_name} to ${newStatus}`);
        res.json({ top_rated: updatedMedicine.top_rated });
    } catch (err) {
        console.error('Error updating top-rated status:', err);
        res.status(500).json({ error: 'Error updating top-rated status' });
    }
});

app.delete('/medicine_info/:id', requireAdmin, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid medicine ID' });
        }
        const result = await Medicine.deleteOne({ _id: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        console.log(`Deleted medicine ID: ${req.params.id}`);
        res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting medicine:', err);
        res.status(500).json({ error: 'Error deleting medicine' });
    }
});

app.post('/medicine_info', requireAdmin, async (req, res) => {
    try {
        const {
            medicine_name,
            image_url,
            price,
            composition,
            uses,
            side_effects,
            manufacturer,
            category,
            excellent_review_percent = 0,
            average_review_percent = 0,
            poor_review_percent = 0,
        } = req.body;

        if (!medicine_name || !price) {
            return res.status(400).json({ error: 'Medicine name and price are required' });
        }

        if (isNaN(price) || price < 0) {
            return res.status(400).json({ error: 'Price must be a valid non-negative number' });
        }

        if (
            (excellent_review_percent && isNaN(excellent_review_percent)) ||
            (average_review_percent && isNaN(average_review_percent)) ||
            (poor_review_percent && isNaN(poor_review_percent))
        ) {
            return res.status(400).json({ error: 'Review percentages must be numbers' });
        }

        const totalReviews = Number(excellent_review_percent) + Number(average_review_percent) + Number(poor_review_percent);
        if (totalReviews > 100) {
            return res.status(400).json({ error: 'Review percentages cannot sum to more than 100%' });
        }

        const existingMedicine = await Medicine.findOne({ medicine_name });
        if (existingMedicine) {
            return res.status(400).json({ error: 'Medicine with this name already exists' });
        }

        const medicine = new Medicine({
            medicine_name,
            image_url,
            price: Number(price),
            composition,
            uses,
            side_effects,
            manufacturer,
            category: category || 'Others',
            excellent_review_percent: Number(excellent_review_percent),
            average_review_percent: Number(average_review_percent),
            poor_review_percent: Number(poor_review_percent),
        });

        await medicine.save();
        console.log(`Added medicine: ${medicine_name}`);
        res.json({ insertedId: medicine._id });
    } catch (err) {
        console.error('Error adding medicine:', err);
        res.status(500).json({ error: 'Error adding medicine' });
    }
});

// Other Routes
app.post('/reviews', async (req, res) => {
    try {
        const { name, email, feedback, rating } = req.body;
        if (!name || !email || !feedback || !rating) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (feedback.length < 10) {
            return res.status(400).json({ error: 'Feedback must be at least 10 characters long' });
        }
        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }
        const review = new Review({ name, email, feedback, rating });
        await review.save();
        console.log(`Created review for ${email}: ${rating} stars`);
        res.json({ insertedId: review._id });
    } catch (err) {
        console.error('Error creating review:', err);
        res.status(500).json({ error: 'Error creating review' });
    }
});

app.get('/reviews', async (req, res) => {
    try {
        const reviews = await Review.find().sort({ date: -1 });
        console.log(`Fetched ${reviews.length} reviews`);
        res.json(reviews);
    } catch (err) {
        console.error('Error fetching reviews:', err);
        res.status(500).json({ error: 'Error fetching reviews' });
    }
});

// Article Routes
app.get('/articles', async (req, res) => {
    try {
        const { page = 1, limit = 10, category, sortBy } = req.query;
        const query = category ? { category } : {};
        const sort = sortBy === 'publication_year_asc' ? { publication_year: 1 } : { publication_year: -1 };
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const articles = await Article.find(query)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit));
        const totalArticles = await Article.countDocuments(query);
        const pages = Math.ceil(totalArticles / parseInt(limit));
        console.log(`Fetched ${articles.length} articles, page ${page}, limit ${limit}, total pages ${pages}`);
        res.json({ articles, pages, totalArticles });
    } catch (err) {
        console.error('Error fetching articles:', err);
        res.status(500).json({ error: 'Error fetching articles' });
    }
});

app.get('/articles/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid article ID' });
        }
        const article = await Article.findById(req.params.id);
        if (!article) {
            return res.status(404).json({ error: 'Article not found' });
        }
        console.log(`Fetched article: ${article.title}`);
        res.json(article);
    } catch (err) {
        console.error('Error fetching article:', err);
        res.status(500).json({ error: 'Error fetching article' });
    }
});

app.get('/articles/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const articles = await Article.find({
            title: { $regex: q, $options: 'i' }
        }).limit(10);
        console.log(`Search found ${articles.length} articles for query: ${q}`);
        res.json(articles);
    } catch (err) {
        console.error('Error searching articles:', err);
        res.status(500).json({ error: 'Error searching articles' });
    }
});

app.get('/categories', async (req, res) => {
    try {
        const categories = await Article.distinct('category');
        console.log('Fetched categories:', categories);
        res.json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ error: 'Error fetching categories' });
    }
});

app.get('/users/:email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) {
            return res.status(400).json({ error: 'User not found', name: null, admin: false });
        }
        console.log(`Fetched user: ${user.email}`);
        res.json({ admin: user.role === 'Admin', name: user.name });
    } catch (err) {
        console.error('Error checking user:', err);
        res.status(500).json({ error: 'Error checking user' });
    }
});

app.post('/users', async (req, res) => {
    try {
        const { email, name } = req.body;
        if (!email || !name) {
            return res.status(400).json({ error: 'Email and name are required' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const user = new User({ email, name });
        await user.save();
        console.log(`Created user: ${email}`);
        res.json({ insertedId: user._id });
    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ error: 'Error creating user' });
    }
});

app.post('/orders', requireAuth, async (req, res) => {
    const { email, name, phoneNumber, address, items, total_price, status } = req.body;
    if (!email || !name || !phoneNumber || !address || !Array.isArray(items) || !total_price) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (items.some(item => !item.productId || !item.medicineName || item.quantity < 1 || item.price < 0)) {
        return res.status(400).json({ error: 'Invalid order items' });
    }
    try {
        const order = {
            email,
            name,
            phoneNumber,
            address,
            items,
            total_price,
            status: status || 'Pending',
            order_date: new Date(),
        };
        const result = await Order.create(order);
        res.json({ orderId: result._id });
    } catch (err) {
        console.error('Error placing order:', err);
        res.status(500).json({ error: `Error placing order: ${err.message}` });
    }
});



// Cart Routes
app.get('/cart', requireAuth, async (req, res) => {
    try {
        const cart = await Cart.findOne({ email: req.user.email });
        res.json(cart ? cart.items : []);
    } catch (err) {
        console.error('Error fetching cart:', err);
        res.status(500).json({ error: 'Error fetching cart' });
    }
});

app.post('/cart', requireAuth, async (req, res) => {
    const { productId, medicineName, price, image_url, quantity = 1 } = req.body;
    if (!productId || !medicineName || !price || quantity < 1) {
        return res.status(400).json({ error: 'Invalid cart item data' });
    }
    try {
        let cart = await Cart.findOne({ email: req.user.email });
        if (!cart) {
            cart = new Cart({ email: req.user.email, items: [] });
        }
        const existingItem = cart.items.find(item => item.productId === productId);
        if (existingItem) {
            existingItem.quantity += quantity;
        } else {
            cart.items.push({ productId, medicineName, price, image_url, quantity });
        }
        await cart.save();
        res.json(cart.items);
    } catch (err) {
        console.error('Error adding to cart:', err);
        res.status(500).json({ error: 'Error adding to cart' });
    }
});
app.put('/cart', requireAuth, async (req, res) => {
    const { items } = req.body;
    if (!Array.isArray(items) || items.some(item => !item.productId || item.quantity < 1)) {
        return res.status(400).json({ error: 'Invalid cart items' });
    }
    try {
        let cart = await Cart.findOne({ email: req.user.email });
        if (!cart) {
            cart = new Cart({ email: req.user.email, items: [] });
        }
        cart.items = items.map(item => ({
            productId: item.productId,
            medicineName: item.medicineName,
            price: item.price,
            image_url: item.image_url,
            quantity: item.quantity,
        }));
        await cart.save();
        res.json(cart.items);
    } catch (err) {
        console.error('Error updating cart:', err);
        res.status(500).json({ error: 'Error updating cart' });
    }
});

app.delete('/cart', requireAuth, async (req, res) => {
    try {
        await Cart.deleteOne({ email: req.user.email });
        res.json({ message: 'Cart cleared' });
    } catch (err) {
        console.error('Error clearing cart:', err);
        res.status(500).json({ error: 'Error clearing cart' });
    }
});

// Voucher Route (unchanged)
app.post('/vouchers/apply', requireAuth, async (req, res) => {
    const { code } = req.body;
    if (!code) {
        return res.status(400).json({ error: 'Voucher code is required' });
    }
    try {
        // Mock voucher logic
        const validVouchers = {
            'rimonsir': 0.1,
            'project_x': 0.2,
        };
        if (!validVouchers[code]) {
            return res.status(400).json({ error: 'Invalid voucher code' });
        }
        res.json({ discount: validVouchers[code] });
    } catch (err) {
        console.error('Error applying voucher:', err);
        res.status(500).json({ error: 'Error applying voucher' });
    }
});

app.get('/orders', requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const skip = (Number(page) - 1) * Number(limit);
        const orders = await Order.find()
            .skip(skip)
            .limit(Number(limit))
            .lean();
        const total = await Order.countDocuments();
        res.json({
            orders,
            total,
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.get('/orders/:email', requireAuth, async (req, res) => {
    const { email } = req.params;
    if (email !== req.user.email) {
        return res.status(403).json({ error: 'Unauthorized to access orders for this email' });
    }
    try {
        const orders = await Order.find({ email });
        res.json(orders);
    } catch (err) {
        console.error('Error fetching orders:', err);
        res.status(500).json({ error: `Error fetching orders: ${err.message}` });
    }
});

app.get('/order/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }
        const order = await Order.findById(req.params.id).populate('items.productId', 'medicine_name price');
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        res.json({
            _id: order._id,
            email: order.email,
            name: order.name,
            phoneNumber: order.phoneNumber,
            status: order.status,
            address: order.address,
            items: order.items,
            total_price: order.total_price,
        });
    } catch (err) {
        console.error('Error fetching order:', err);
        res.status(500).json({ error: 'Error fetching order' });
    }
});

app.put('/orders/:id', requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }
        if (!status || !['Pending', 'Shipped', 'Paid'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (order.status === 'Paid') {
            return res.status(400).json({ error: 'Cannot update a Paid order' });
        }
        const result = await Order.updateOne(
            { _id: req.params.id },
            { $set: { status } }
        );
        if (result.modifiedCount === 0) {
            return res.status(400).json({ error: 'Order not found or status unchanged' });
        }
        console.log(`Updated order ID: ${req.params.id} to status: ${status}`);
        res.json({ modifiedCount: result.modifiedCount });
    } catch (err) {
        console.error('Error updating order:', err);
        res.status(500).json({ error: 'Error updating order' });
    }
});


app.delete('/orders/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    if (!/^[0-9a-fA-F]{24}$/.test(id)) {
        return res.status(400).json({ error: 'Invalid order ID' });
    }
    try {
        const order = await Order.findOne({ _id: new mongoose.Types.ObjectId(id), email: req.user.email });
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (order.status === 'Paid' || order.status === 'Shipped') {
            return res.status(400).json({ error: `Cannot cancel a ${order.status} order` });
        }
        await Order.deleteOne({ _id: new mongoose.Types.ObjectId(id) });
        res.json({ message: 'Order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling order:', err);
        res.status(500).json({ error: `Error cancelling order: ${err.message}` });
    }
});

app.post('/payments', async (req, res) => {
    try {
        const { orderId, email, paymentMethod, amount } = req.body;
        if (!orderId || !email || !paymentMethod || !amount) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (!mongoose.Types.ObjectId.isValid(orderId)) {
            return res.status(400).json({ error: 'Invalid order ID' });
        }
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        if (order.email !== email) {
            return res.status(403).json({ error: 'Unauthorized: Email does not match order' });
        }
        if (order.status === 'Paid') {
            return res.status(400).json({ error: 'Order already paid' });
        }
        if (parseFloat(amount).toFixed(2) !== parseFloat(order.total_price).toFixed(2)) {
            return res.status(400).json({ error: 'Amount does not match order total' });
        }
        console.log(`Processed payment for order ID: ${orderId}, email: ${email}, method: ${paymentMethod}, amount: ${amount}`);
        res.json({ success: true, orderId, amount });
    } catch (err) {
        console.error('Error processing payment:', err);
        res.status(500).json({ error: 'Error processing payment' });
    }
});

app.put('/users/admin', requireAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Valid email is required' });
        }
        if (email === req.user.email) {
            return res.status(400).json({ error: 'Cannot modify your own admin status' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.role === 'Admin') {
            return res.status(400).json({ error: 'User is already an admin' });
        }
        const result = await User.updateOne(
            { email },
            { $set: { role: 'Admin' } }
        );
        console.log(`Updated user ${email} to admin, modified: ${result.modifiedCount}`);
        res.json({ modifiedCount: result.modifiedCount });
    } catch (err) {
        console.error('Error making admin:', err);
        res.status(500).json({ error: 'Error making admin' });
    }
});


app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});