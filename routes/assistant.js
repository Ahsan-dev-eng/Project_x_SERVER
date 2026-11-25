const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const { writeLimiter } = require('../middleware/rateLimiter');
const { handleValidation, chatValidation } = require('../middleware/validators');

const router = express.Router();

// The Gemini client is created lazily so this module can be imported without
// the API key being present (the startup check lives in index.js).
const genAI = process.env.API_KEY ? new GoogleGenerativeAI(process.env.API_KEY) : null;

/**
 * POST /chat - the MediBot assistant.
 */
router.post('/chat', writeLimiter, chatValidation, handleValidation, async (req, res) => {
    const { message } = req.body;
    if (!genAI) {
        return res.status(503).json({ error: 'Chat assistant is not configured on this server.' });
    }
    try {
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

Be effective — deliver clear, practical answers.

Be efficient — keep responses short, direct, and easy to follow.

Be user-friendly — simple, everyday language that anyone can understand.

Be sentimental — show empathy and care (acknowledge discomfort, reassure the user).

Be knowledgeable — trustworthy, reliable, and commonly known healthcare information.

User query: ${message}
`;

        let model;
        try {
            model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
            const result = await model.generateContent(systemPrompt);
            const response = result.response.text();
            return res.json({ reply: response });
        } catch (modelErr) {
            console.warn('Primary model (gemini-1.5-flash) failed:', modelErr.message);
            try {
                model = genAI.getGenerativeModel({ model: 'gemini-pro' });
                const result = await model.generateContent(systemPrompt);
                const response = result.response.text();
                return res.json({ reply: response });
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
            return res.status(401).json({ error: 'Invalid API key. Please contact support.' });
        }
        if (err.response && err.response.status === 400 && err.message.includes('API_KEY_INVALID')) {
            return res.status(400).json({ error: 'Invalid API key. Please check the API key configuration.' });
        }
        if (err.response && err.response.status === 429) {
            return res.status(429).json({ error: 'Rate limit exceeded. Please try again later.' });
        }
        if (err.message.includes('model')) {
            return res.status(400).json({ error: 'Invalid or unavailable model specified. Please try again later.' });
        }
        return res.status(500).json({ error: 'Error generating response. Please try again.' });
    }
});

module.exports = router;
