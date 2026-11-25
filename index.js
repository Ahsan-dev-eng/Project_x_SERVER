const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');

// `.env.local` is loaded first so it always wins over a plain `.env`.
dotenv.config({ path: '.env.local' });
dotenv.config();

const { getJwtSecret, initializeFirebaseAdmin } = require('./middleware/firebase');

const authRoutes = require('./routes/auth');
const catalogRoutes = require('./routes/catalog');
const appointmentsRoutes = require('./routes/appointments');
const commerceRoutes = require('./routes/commerce');
const assistantRoutes = require('./routes/assistant');

const app = express();
const port = process.env.PORT || 3001;

// Behind a reverse proxy (nginx, Heroku, Render...) set TRUST_PROXY so that
// rate limiting sees the real client IP instead of the proxy's.
app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) : false);

// ---------------------------------------------------------------------------
// CORS - explicitly allow the frontend origin(s)
// ---------------------------------------------------------------------------
const allowedOrigins = (process.env.CLIENT_ORIGIN || 'http://localhost:3000')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        // Allow same-origin / non-browser callers (no Origin header).
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        // Not allowed: respond without CORS headers so the browser blocks it.
        console.warn(`⚠️  Blocked CORS request from origin: ${origin}`);
        return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
}));

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------
app.use(helmet({
    // The API serves JSON to a separate frontend origin.
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Log requests
app.use((req, res, next) => {
    console.log(`Request: ${req.method} ${req.originalUrl}`);
    next();
});

// ---------------------------------------------------------------------------
// MongoDB connection
// ---------------------------------------------------------------------------
const uri = process.env.MONGODB_URI;
if (!uri) {
    console.error('❌ MONGODB_URI is not defined. Add it to .env.local.');
    process.exit(1);
}

mongoose.connect(uri)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch((err) => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// ---------------------------------------------------------------------------
// Firebase Admin SDK - enables native Firebase ID token verification
// ---------------------------------------------------------------------------
initializeFirebaseAdmin();

// ---------------------------------------------------------------------------
// Startup checks
// ---------------------------------------------------------------------------
try {
    getJwtSecret();
    console.log('✅ JWT_SECRET loaded');
} catch (err) {
    if (process.env.NODE_ENV === 'production') {
        console.error(`❌ ${err.message}`);
        process.exit(1);
    }
    console.error(`⚠️  ${err.message}`);
    console.error('   Legacy session tokens will be rejected. Set JWT_SECRET in .env.local.');
}

if (!process.env.API_KEY) {
    console.error('❌ GEMINI_API_KEY is not defined in .env.local - the /chat assistant will be unavailable.');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use(authRoutes);
app.use(catalogRoutes);
app.use(appointmentsRoutes);
app.use(commerceRoutes);
app.use(assistantRoutes);

// ---------------------------------------------------------------------------
// 404 - unmatched routes return clean JSON so `getApiErrorMessage()` works
// ---------------------------------------------------------------------------
app.use((req, res) => {
    res.status(404).json({ error: `Endpoint not found: ${req.method} ${req.originalUrl}` });
});

// ---------------------------------------------------------------------------
// Central error handler
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (res.headersSent) return next(err);
    return res.status(500).json({ error: 'Internal server error' });
});

if (require.main === module) {
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
}

module.exports = app;
