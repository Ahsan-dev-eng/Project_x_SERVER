const express = require('express');
const mongoose = require('mongoose');

const { Medicine, Doctor, Appointment, Article, Review } = require('../models');
const { requireAdmin } = require('../middleware/auth');
const { writeLimiter, reviewLimiter } = require('../middleware/rateLimiter');
const {
    handleValidation,
    paginationValidation,
    medicineCreateValidation,
    medicineIdParamValidation,
    doctorIdParamValidation,
    doctorUpdateValidation,
    reviewValidation,
} = require('../middleware/validators');

const router = express.Router();

// ---------------------------------------------------------------------------
// Medicines (products)
// ---------------------------------------------------------------------------

/** GET /medicine_info - paginated catalogue with filters. */
router.get('/medicine_info', paginationValidation, handleValidation, async (req, res) => {
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

        return res.json({
            medicines,
            total,
            page: Number(page),
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching medicines:', err);
        return res.status(500).json({ error: 'Error fetching medicines' });
    }
});

/** GET /medicine_info/search?q= */
router.get('/medicine_info/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const medicines = await Medicine.find({
            medicine_name: { $regex: q, $options: 'i' }
        });
        console.log(`Search results for "${q}":`, medicines.length);
        return res.json(medicines);
    } catch (err) {
        console.error('Error searching medicines:', err);
        return res.status(500).json({ error: 'Error searching medicines' });
    }
});

/** GET /medicine_info/:id */
router.get('/medicine_info/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid medicine ID' });
        }
        const medicine = await Medicine.findById(req.params.id);
        if (!medicine) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        console.log(`Fetched medicine: ${medicine.medicine_name}`);
        return res.json(medicine);
    } catch (err) {
        console.error('Error fetching medicine:', err);
        return res.status(500).json({ error: 'Error fetching medicine' });
    }
});

/** PATCH /medicine_info/:id/top-rated - admin only. */
router.patch('/medicine_info/:id/top-rated', requireAdmin, writeLimiter, medicineIdParamValidation, handleValidation, async (req, res) => {
    try {
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
        return res.json({ top_rated: updatedMedicine.top_rated });
    } catch (err) {
        console.error('Error updating top-rated status:', err);
        return res.status(500).json({ error: 'Error updating top-rated status' });
    }
});

/** DELETE /medicine_info/:id - admin only. */
router.delete('/medicine_info/:id', requireAdmin, writeLimiter, medicineIdParamValidation, handleValidation, async (req, res) => {
    try {
        const result = await Medicine.deleteOne({ _id: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Medicine not found' });
        }
        console.log(`Deleted medicine ID: ${req.params.id}`);
        return res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting medicine:', err);
        return res.status(500).json({ error: 'Error deleting medicine' });
    }
});

/** POST /medicine_info - create a product. Admin only. */
router.post('/medicine_info', requireAdmin, writeLimiter, medicineCreateValidation, handleValidation, async (req, res) => {
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
        return res.json({ insertedId: medicine._id });
    } catch (err) {
        console.error('Error adding medicine:', err);
        return res.status(500).json({ error: 'Error adding medicine' });
    }
});

// ---------------------------------------------------------------------------
// Doctors
// ---------------------------------------------------------------------------

/** GET /doctor_info/specializations - registered before /doctor_info/:id. */
router.get('/doctor_info/specializations', async (req, res) => {
    try {
        const specializations = await Doctor.distinct('specializations');
        console.log(`Fetched ${specializations.length} unique specializations`);
        return res.json(specializations);
    } catch (err) {
        console.error('Error fetching specializations:', err);
        return res.status(500).json({ error: 'Error fetching specializations' });
    }
});

/** GET /doctor_info - paginated directory with filters. */
router.get('/doctor_info', paginationValidation, handleValidation, async (req, res) => {
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

        return res.json({
            doctors,
            total,
            page: Number(page),
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching doctors:', err);
        return res.status(500).json({ error: 'Error fetching doctors' });
    }
});

/** GET /doctor_info/search?q= */
router.get('/doctor_info/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const doctors = await Doctor.find({
            name: { $regex: q, $options: 'i' }
        });
        console.log(`Search results for "${q}":`, doctors.length);
        return res.json(doctors);
    } catch (err) {
        console.error('Error searching doctors:', err);
        return res.status(500).json({ error: 'Error searching doctors' });
    }
});

/** GET /doctor_info/:id */
router.get('/doctor_info/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const doctor = await Doctor.findById(req.params.id);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Fetched doctor: ${doctor.name}`);
        return res.json(doctor);
    } catch (err) {
        console.error('Error fetching doctor:', err);
        return res.status(500).json({ error: 'Error fetching doctor' });
    }
});

/** PUT /doctor_info/:id - admin only. */
router.put('/doctor_info/:id', requireAdmin, writeLimiter, doctorUpdateValidation, handleValidation, async (req, res) => {
    try {
        const updates = req.body;
        const allowedUpdates = [
            'name', 'image', 'qualifications', 'specializations', 'availability',
            'department', 'experience', 'contact', 'hospital', 'consultation_fee',
            'location', 'rating', 'top_rated'
        ];
        const isValidUpdate = Object.keys(updates).every((key) => allowedUpdates.includes(key));
        if (!isValidUpdate) {
            return res.status(400).json({ error: 'Invalid updates' });
        }
        const doctor = await Doctor.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Updated doctor: ${doctor.name}`);
        return res.json(doctor);
    } catch (err) {
        console.error('Error updating doctor:', err);
        return res.status(500).json({ error: 'Error updating doctor' });
    }
});

/** PATCH /doctor_info/:id/top-rated - admin only. */
router.patch('/doctor_info/:id/top-rated', requireAdmin, writeLimiter, doctorIdParamValidation, handleValidation, async (req, res) => {
    try {
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
        return res.json({ top_rated: updatedDoctor.top_rated });
    } catch (err) {
        console.error('Error updating top-rated status:', err);
        return res.status(500).json({ error: 'Error updating top-rated status' });
    }
});

/** DELETE /doctor_info/:id - admin only. */
router.delete('/doctor_info/:id', requireAdmin, writeLimiter, doctorIdParamValidation, handleValidation, async (req, res) => {
    try {
        const result = await Doctor.deleteOne({ _id: req.params.id });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }
        console.log(`Deleted doctor ID: ${req.params.id}`);
        return res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting doctor:', err);
        return res.status(500).json({ error: 'Error deleting doctor' });
    }
});

/**
 * GET /doctors/:doctorId/availability
 * Matches `endpoints.doctorAvailability(id)` in the frontend contract.
 */
const getDoctorAvailability = async (req, res) => {
    try {
        const doctorId = req.params.doctorId;
        if (!mongoose.Types.ObjectId.isValid(doctorId)) {
            return res.status(400).json({ error: 'Invalid doctor ID' });
        }
        const doctor = await Doctor.findById(doctorId);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }

        const { startDate } = req.query;
        const today = startDate ? new Date(startDate) : new Date();
        today.setHours(0, 0, 0, 0);

        // Use default working hours if not specified
        const workingHours = doctor.workingHours || { start: '09:00', end: '17:00' };
        const workingStartHour = parseInt(workingHours.start.split(':')[0], 10);
        const workingEndHour = parseInt(workingHours.end.split(':')[0], 10);

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
                if (!appointments.some((appt) => appt.time === time)) {
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

        return res.json({ availability });
    } catch (err) {
        console.error('Error fetching doctor availability:', err);
        return res.status(500).json({ error: 'Error fetching availability' });
    }
};

router.get('/doctors/:doctorId/availability', getDoctorAvailability);
// Convenience alias matching the /doctor_info naming used elsewhere.
router.get('/doctor_info/:id/availability', getDoctorAvailability);

// ---------------------------------------------------------------------------
// Reviews
// ---------------------------------------------------------------------------

/** POST /reviews */
router.post('/reviews', reviewLimiter, reviewValidation, handleValidation, async (req, res) => {
    try {
        const { name, email, feedback, rating } = req.body;
        const review = new Review({ name, email, feedback, rating });
        await review.save();
        console.log(`Created review for ${email}: ${rating} stars`);
        return res.json({ insertedId: review._id });
    } catch (err) {
        console.error('Error creating review:', err);
        return res.status(500).json({ error: 'Error creating review' });
    }
});

/** GET /reviews */
router.get('/reviews', async (req, res) => {
    try {
        const reviews = await Review.find().sort({ date: -1 });
        console.log(`Fetched ${reviews.length} reviews`);
        return res.json(reviews);
    } catch (err) {
        console.error('Error fetching reviews:', err);
        return res.status(500).json({ error: 'Error fetching reviews' });
    }
});

// ---------------------------------------------------------------------------
// Articles & categories
// ---------------------------------------------------------------------------

/** GET /articles */
router.get('/articles', paginationValidation, handleValidation, async (req, res) => {
    try {
        const { page = 1, limit = 10, category, sortBy } = req.query;
        const query = category ? { category } : {};
        const sort = sortBy === 'publication_year_asc' ? { publication_year: 1 } : { publication_year: -1 };
        const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);
        const articles = await Article.find(query)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit, 10));
        const totalArticles = await Article.countDocuments(query);
        const pages = Math.ceil(totalArticles / parseInt(limit, 10));
        console.log(`Fetched ${articles.length} articles, page ${page}, limit ${limit}, total pages ${pages}`);
        return res.json({ articles, pages, totalArticles });
    } catch (err) {
        console.error('Error fetching articles:', err);
        return res.status(500).json({ error: 'Error fetching articles' });
    }
});

/** GET /articles/search?q= - registered before /articles/:id. */
router.get('/articles/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const articles = await Article.find({
            title: { $regex: q, $options: 'i' }
        }).limit(10);
        console.log(`Search found ${articles.length} articles for query: ${q}`);
        return res.json(articles);
    } catch (err) {
        console.error('Error searching articles:', err);
        return res.status(500).json({ error: 'Error searching articles' });
    }
});

/** GET /articles/:id */
router.get('/articles/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid article ID' });
        }
        const article = await Article.findById(req.params.id);
        if (!article) {
            return res.status(404).json({ error: 'Article not found' });
        }
        console.log(`Fetched article: ${article.title}`);
        return res.json(article);
    } catch (err) {
        console.error('Error fetching article:', err);
        return res.status(500).json({ error: 'Error fetching article' });
    }
});

/** GET /categories */
router.get('/categories', async (req, res) => {
    try {
        const categories = await Article.distinct('category');
        console.log('Fetched categories:', categories);
        return res.json(categories);
    } catch (err) {
        console.error('Error fetching categories:', err);
        return res.status(500).json({ error: 'Error fetching categories' });
    }
});

module.exports = router;
