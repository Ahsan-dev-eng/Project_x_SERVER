const express = require('express');
const mongoose = require('mongoose');

const { Appointment, Doctor } = require('../models');
const { requireAuth, requireAdmin, requireOwnerOrAdmin } = require('../middleware/auth');
const { bookingLimiter, writeLimiter } = require('../middleware/rateLimiter');
const {
    handleValidation,
    paginationValidation,
    appointmentCreateValidation,
    appointmentUpdateValidation,
} = require('../middleware/validators');

const router = express.Router();

/**
 * POST /appointments - book a slot.
 */
router.post('/appointments', requireAuth, bookingLimiter, appointmentCreateValidation, handleValidation, async (req, res) => {
    const { doctorId, userEmail, date, time } = req.body;
    try {
        if (userEmail !== req.user.email && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Unauthorized to book for this email' });
        }

        const doctor = await Doctor.findById(doctorId);
        if (!doctor) {
            return res.status(404).json({ error: 'Doctor not found' });
        }

        // Check for existing appointment with same doctor, date, and time
        const existingAppointment = await Appointment.findOne({
            doctorId,
            date: new Date(date),
            time,
        });
        if (existingAppointment) {
            return res.status(400).json({ error: 'This time slot is already booked. Please choose another time.' });
        }

        const appointment = new Appointment({ doctorId, userEmail, date, time });
        await appointment.save();
        console.log(`Created appointment for doctor ID: ${doctorId}, user: ${userEmail}`);
        return res.json({ insertedId: appointment._id });
    } catch (err) {
        console.error('Error creating appointment:', err);
        return res.status(500).json({ error: 'Error creating appointment' });
    }
});

/** GET /appointments - every appointment. Admin only. */
router.get('/appointments', requireAdmin, paginationValidation, handleValidation, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const skip = (Number(page) - 1) * Number(limit);
        const appointments = await Appointment.find()
            .skip(skip)
            .limit(Number(limit))
            .lean();
        const total = await Appointment.countDocuments();
        return res.json({
            appointments,
            total,
            pages: Math.ceil(total / Number(limit)),
        });
    } catch (err) {
        console.error('Error fetching appointments:', err);
        return res.status(500).json({ error: 'Error fetching appointments' });
    }
});

/**
 * GET /appointments/:id - a single appointment by MongoDB id.
 * Matches `endpoints.appointmentById(id)` in the frontend contract.
 *
 * This route is registered BEFORE /appointments/:userEmail. A non ObjectId
 * segment (i.e. an email address) falls through to the email route so the two
 * endpoints never collide.
 */
router.get('/appointments/:id', requireOwnerOrAdmin, async (req, res, next) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return next();
    }
    try {
        const appointment = await Appointment.findById(id).populate('doctorId', 'name consultation_fee');
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        if (!req.isAdmin && appointment.userEmail !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to access this appointment' });
        }
        return res.json(appointment);
    } catch (err) {
        console.error('Error fetching appointment:', err);
        return res.status(500).json({ error: 'Error fetching appointment' });
    }
});

/** GET /appointments/:userEmail - the appointments belonging to a user. Owner or admin only. */
router.get('/appointments/:userEmail', requireOwnerOrAdmin, async (req, res) => {
    const { userEmail } = req.params;
    try {
        if (!req.isAdmin && userEmail !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to access appointments for this email' });
        }
        const appointments = await Appointment.find({ userEmail })
            .populate('doctorId', 'name consultation_fee');
        console.log(`Fetched ${appointments.length} appointments for ${userEmail}`);
        return res.json(appointments);
    } catch (err) {
        console.error('Error fetching appointments:', err);
        return res.status(500).json({ error: 'Error fetching appointments' });
    }
});


/** PUT /appointments/:id - reschedule an appointment. Owner or admin only. */
router.put('/appointments/:id', requireOwnerOrAdmin, bookingLimiter, appointmentUpdateValidation, handleValidation, async (req, res) => {
    const { date, time } = req.body;
    try {
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        if (!req.isAdmin && appointment.userEmail !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to modify this appointment' });
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
        return res.json({ modifiedCount: updatedAppointment ? 1 : 0 });
    } catch (err) {
        console.error('Error updating appointment:', err);
        return res.status(500).json({ error: 'Error updating appointment' });
    }
});

/** PUT /appointments/:id/pay - mark an appointment as paid. Owner or admin only. */
router.put('/appointments/:id/pay', requireOwnerOrAdmin, bookingLimiter, appointmentUpdateValidation, handleValidation, async (req, res) => {
    try {
        const appointment = await Appointment.findById(req.params.id);
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        if (!req.isAdmin && appointment.userEmail !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to pay for this appointment' });
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
        return res.json({ modifiedCount: updatedAppointment ? 1 : 0 });
    } catch (err) {
        console.error('Error paying for appointment:', err);
        return res.status(500).json({ error: 'Error paying for appointment' });
    }
});

/**
 * DELETE /appointments/:id - cancel an appointment. Owner or admin only.
 * DELETE /appointment/:id is kept as an alias for backwards compatibility.
 */
const deleteAppointment = async (req, res) => {
    const { id } = req.params;
    try {
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid appointment ID' });
        }
        const appointment = await Appointment.findById(id);
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found' });
        }
        if (!req.isAdmin && appointment.userEmail !== req.user.email) {
            return res.status(403).json({ error: 'Unauthorized to cancel this appointment' });
        }
        const result = await Appointment.deleteOne({ _id: id });
        console.log(`Deleted appointment ID: ${id}`);
        return res.json({ deletedCount: result.deletedCount });
    } catch (err) {
        console.error('Error deleting appointment:', err);
        return res.status(500).json({ error: 'Error deleting appointment' });
    }
};

router.delete('/appointments/:id', requireOwnerOrAdmin, writeLimiter, deleteAppointment);
router.delete('/appointment/:id', requireOwnerOrAdmin, writeLimiter, deleteAppointment);

module.exports = router;
