import { Router } from 'express';
import * as authController from '../controllers/auth.Controller';

const router = Router();

router.post('/register', authController.register);
router.post('/verify', authController.verify);
router.post('/resend-otp', authController.resendOTP);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.post('/verify-reset-otp', authController.verifyResetOTP);

export default router;
