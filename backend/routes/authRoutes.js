const express = require('express');
const { body } = require('express-validator');
const { register, login, verifyEmail, resendVerification, refresh, logout, userInfo, forgotPassword, verifyResetOtp, resetPassword } = require('../controllers/authController');
const router = express.Router();

router.post('/register', [
    body('name').isLength({ min: 3 }).withMessage('Name must be at least 3 characters long'),
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], register);
router.post('/login', [
    body('emailOrUsername').notEmpty().withMessage('Email or username is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], login);
router.post('/verify-email', verifyEmail);
router.post('/resend-verification', resendVerification);
router.get('/refresh', refresh);
router.get('/userInfo', userInfo);
router.post('/logout', logout);

router.post("/forgot-password", forgotPassword)
router.post("/verify-reset-otp", verifyResetOtp)
router.post("/reset-password", resetPassword)
module.exports = router;