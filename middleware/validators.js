const { body, param, query, validationResult } = require('express-validator');
const mongoose = require('mongoose');

/**
 * Strict ObjectId check.
 *
 * `mongoose.Types.ObjectId.isValid()` also accepts any 12 character string,
 * so it is combined with a 24 hex character test. This keeps route params such
 * as `/appointments/:id` from colliding with `/appointments/:userEmail`.
 */
const isValidObjectId = (value) => (
    typeof value === 'string'
    && mongoose.Types.ObjectId.isValid(value)
    && /^[0-9a-fA-F]{24}$/.test(value)
);

/**
 * Lowercases and trims an email without applying provider specific rewrites
 * (express-validator's `normalizeEmail()` strips dots from Gmail addresses,
 * which would break lookups against existing accounts).
 */
const sanitizeEmail = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : value);

const emailField = (field = 'email') => body(field)
    .customSanitizer(sanitizeEmail)
    .isEmail()
    .withMessage('A valid email is required');

/**
 * Terminates the request with a consistent `400 { error }` payload whenever a
 * validation chain fails, so `getApiErrorMessage()` always receives clean JSON.
 */
const handleValidation = (req, res, next) => {
    const result = validationResult(req);
    if (result.isEmpty()) return next();

    const errors = result.array();
    return res.status(400).json({
        error: errors[0].msg,
        errors: errors.map((e) => ({ field: e.path, message: e.msg })),
    });
};

/** Shared pagination query parameters. */
const paginationValidation = [
    query('page').optional().isInt({ min: 1 }).withMessage('page must be a positive integer').toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('limit must be between 1 and 100').toInt(),
];

const loginValidation = [
    emailField(),
    body('firebaseToken').isString().trim().notEmpty().withMessage('Firebase token is required'),
];

const userCreateValidation = [
    emailField(),
    body('name').isString().trim().notEmpty().withMessage('Name is required').isLength({ max: 120 }),
    // NOTE: `role` is intentionally NOT accepted from the client. The role is
    // always assigned server side ('User'); admin is granted only through
    // PUT /users/admin.
];

const makeAdminValidation = [
    emailField(),
];

const orderCreateValidation = [
    emailField(),
    body('name').isString().trim().notEmpty().withMessage('Name is required').isLength({ max: 120 }),
    body('phoneNumber').isString().trim().notEmpty().withMessage('Phone number is required').isLength({ max: 40 }),
    body('address').isString().trim().notEmpty().withMessage('Address is required').isLength({ max: 400 }),
    body('items').isArray({ min: 1 }).withMessage('At least one order item is required'),
    body('items.*.productId').isString().trim().notEmpty().withMessage('Each item requires a productId'),
    body('items.*.medicineName').isString().trim().notEmpty().withMessage('Each item requires a medicineName'),
    body('items.*.quantity').isInt({ min: 1 }).withMessage('Item quantity must be an integer of at least 1'),
    body('items.*.price').isFloat({ min: 0 }).withMessage('Item price must be a non-negative number'),
    body('total_price').isFloat({ min: 0 }).withMessage('Total price must be a non-negative number'),
];

const orderStatusValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid order ID'),
    body('status').isIn(['Pending', 'Shipped', 'Paid']).withMessage('Invalid status'),
];

const orderIdParamValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid order ID'),
];

const orderEmailParamValidation = [
    param('email').customSanitizer(sanitizeEmail).isEmail().withMessage('A valid email is required'),
];


const appointmentCreateValidation = [
    body('doctorId').custom(isValidObjectId).withMessage('Invalid doctor ID'),
    emailField('userEmail'),
    body('date').isISO8601().withMessage('A valid date is required').toDate(),
    body('time').isString().trim().matches(/^\d{2}:\d{2}$/).withMessage('Time must be in HH:mm format'),
];

const appointmentUpdateValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid appointment ID'),
    body('date').isISO8601().withMessage('A valid date is required').toDate(),
    body('time').isString().trim().matches(/^\d{2}:\d{2}$/).withMessage('Time must be in HH:mm format'),
];

const appointmentIdParamValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid appointment ID'),
];

const doctorIdParamValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid doctor ID'),
];

const doctorUpdateValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid doctor ID'),
    body('name').optional().isString().trim().notEmpty().withMessage('Name must be a non-empty string'),
    body('image').optional().isString(),
    body('qualifications').optional().isString(),
    body('specializations').optional().isString(),
    body('availability').optional().isArray().withMessage('availability must be an array'),
    body('department').optional().isString(),
    body('experience').optional().isFloat({ min: 0 }).withMessage('experience must be a non-negative number'),
    body('contact').optional().isString(),
    body('hospital').optional().isString(),
    body('consultation_fee').optional().isFloat({ min: 0 }).withMessage('consultation_fee must be a non-negative number'),
    body('location').optional().isString(),
    body('rating').optional().isFloat({ min: 0, max: 5 }).withMessage('rating must be between 0 and 5'),
    body('top_rated').optional().isBoolean().withMessage('top_rated must be a boolean'),
];

const medicineCreateValidation = [
    body('medicine_name').isString().trim().notEmpty().withMessage('Medicine name is required').isLength({ max: 200 }),
    body('image_url').optional({ values: 'falsy' }).isString().withMessage('Image URL must be a string'),
    body('price').isFloat({ min: 0 }).withMessage('Price must be a non-negative number'),
    body('composition').optional().isString(),
    body('uses').optional().isString(),
    body('side_effects').optional().isString(),
    body('manufacturer').optional().isString(),
    body('category').optional().isString(),
    body('excellent_review_percent').optional().isFloat({ min: 0, max: 100 }).withMessage('Excellent review percent must be between 0 and 100'),
    body('average_review_percent').optional().isFloat({ min: 0, max: 100 }).withMessage('Average review percent must be between 0 and 100'),
    body('poor_review_percent').optional().isFloat({ min: 0, max: 100 }).withMessage('Poor review percent must be between 0 and 100'),
];

const medicineIdParamValidation = [
    param('id').custom(isValidObjectId).withMessage('Invalid medicine ID'),
];


const reviewValidation = [
    body('name').isString().trim().notEmpty().withMessage('Name is required').isLength({ max: 120 }),
    emailField(),
    body('feedback').isString().trim().isLength({ min: 10 }).withMessage('Feedback must be at least 10 characters long').isLength({ max: 2000 }),
    body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
];

const cartAddValidation = [
    body('productId').isString().trim().notEmpty().withMessage('Product ID is required'),
    body('medicineName').isString().trim().notEmpty().withMessage('Medicine name is required'),
    body('price').isFloat({ min: 0 }).withMessage('Price must be a non-negative number'),
    body('image_url').optional({ values: 'falsy' }).isString(),
    body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be an integer of at least 1'),
];

const cartUpdateValidation = [
    body('items').isArray({ min: 1 }).withMessage('Items must be a non-empty array'),
    body('items.*.productId').isString().trim().notEmpty().withMessage('Each item requires a productId'),
    body('items.*.medicineName').optional().isString(),
    body('items.*.price').optional().isFloat({ min: 0 }),
    body('items.*.image_url').optional().isString(),
    body('items.*.quantity').isInt({ min: 1 }).withMessage('Item quantity must be an integer of at least 1'),
];

const paymentValidation = [
    body('orderId').custom(isValidObjectId).withMessage('Invalid order ID'),
    emailField(),
    body('paymentMethod').isString().trim().notEmpty().withMessage('Payment method is required').isLength({ max: 60 }),
    body('amount').isFloat({ min: 0 }).withMessage('Amount must be a non-negative number'),
];

const voucherValidation = [
    body('code').isString().trim().notEmpty().withMessage('Voucher code is required').isLength({ max: 60 }),
];

const chatValidation = [
    body('message').isString().trim().notEmpty().withMessage('Message is required').isLength({ max: 2000 }),
];

module.exports = {
    handleValidation,
    isValidObjectId,
    sanitizeEmail,
    paginationValidation,
    loginValidation,
    userCreateValidation,
    makeAdminValidation,
    orderCreateValidation,
    orderStatusValidation,
    orderIdParamValidation,
    orderEmailParamValidation,
    appointmentCreateValidation,
    appointmentUpdateValidation,
    appointmentIdParamValidation,
    doctorIdParamValidation,
    doctorUpdateValidation,
    medicineCreateValidation,
    medicineIdParamValidation,
    reviewValidation,
    cartAddValidation,
    cartUpdateValidation,
    paymentValidation,
    voucherValidation,
    chatValidation,
};
