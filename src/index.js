import 'dotenv/config';
import express from 'express';
import admin from 'firebase-admin';
import fetch from 'node-fetch';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import serviceAccount from '../serviceAccountKey.json' with { type: 'json' };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(express.json());
app.use(helmet());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit IP to 100 requests per windowMs
});
app.use(limiter);

// Logger Setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'otp-auth-service' },
  transports: [
    new winston.transports.Console(),
  ],
});

// Firebase Auth Base URL
const authBaseUrl = process.env.FIREBASE_AUTH_EMULATOR_HOST
  ? `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}/identitytoolkit.googleapis.com/v1`
  : 'https://identitytoolkit.googleapis.com/v1';

// Send Verification Code
async function sendVerificationCode(phoneNumber) {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey && !process.env.FIREBASE_AUTH_EMULATOR_HOST) {
    logger.error('Missing FIREBASE_WEB_API_KEY');
    throw new Error('Server misconfiguration');
  }

  const url = `${authBaseUrl}/accounts:sendVerificationCode?key=${apiKey || 'fakeKey'}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneNumber }),
  });
  const body = await response.json();
  if (body.error) {
    logger.error('Error sending verification code', body.error);
    throw new Error(body.error.message);
  }

  logger.info('Verification code sent', { phoneNumber });
  return body.sessionInfo;
}

// Verify OTP
async function verifyOtp(sessionInfo, code) {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  const url = `${authBaseUrl}/accounts:signInWithPhoneNumber?key=${apiKey || 'fakeKey'}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionInfo, code }),
  });
  const body = await response.json();
  if (body.error) {
    logger.error('Error verifying OTP', body.error);
    throw new Error(body.error.message);
  }
  return body.idToken;
}

// Routes
app.post('/signup/request-otp', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required.' });
  }

  try {
    await admin.auth().getUserByPhoneNumber(phoneNumber);
    return res.status(400).json({ error: 'Phone number already registered.' });
  } catch (error) {
    if (error.code === 'auth/user-not-found') {
      try {
        const sessionInfo = await sendVerificationCode(phoneNumber);
        return res.json({ sessionInfo });
      } catch (err) {
        logger.error('Error in /signup/request-otp', err);
        return res.status(500).json({ error: 'Failed to send verification code.' });
      }
    } else {
      logger.error('Error checking user by phone number', error);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  }
});

app.post('/signup/verify-otp', async (req, res) => {
  const { sessionInfo, code } = req.body;
  if (!sessionInfo || !code) {
    return res.status(400).json({ error: 'Session info and code are required.' });
  }

  try {
    const idToken = await verifyOtp(sessionInfo, code);
    const decoded = await admin.auth().verifyIdToken(idToken);
    return res.json({ uid: decoded.uid, idToken });
  } catch (error) {
    logger.error('Error in /signup/verify-otp', error);
    return res.status(400).json({ error: 'Invalid or expired OTP.' });
  }
});

app.post('/signin/request-otp', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required.' });
  }

  try {
    await admin.auth().getUserByPhoneNumber(phoneNumber);
    const sessionInfo = await sendVerificationCode(phoneNumber);
    return res.json({ sessionInfo });
  } catch (error) {
    if (error.code === 'auth/user-not-found') {
      return res.status(400).json({ error: 'Phone number not registered.' });
    } else {
      logger.error('Error in /signin/request-otp', error);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  }
});

app.post('/signin/verify-otp', async (req, res) => {
  const { sessionInfo, code } = req.body;
  if (!sessionInfo || !code) {
    return res.status(400).json({ error: 'Session info and code are required.' });
  }

  try {
    const idToken = await verifyOtp(sessionInfo, code);
    const decoded = await admin.auth().verifyIdToken(idToken);
    const customToken = await admin.auth().createCustomToken(decoded.uid);
    return res.json({ uid: decoded.uid, customToken });
  } catch (error) {
    logger.error('Error in /signin/verify-otp', error);
    return res.status(400).json({ error: 'Invalid or expired OTP.' });
  }
});

// Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', err);
  res.status(500).json({ error: 'Internal server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
