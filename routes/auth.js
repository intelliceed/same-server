// outsource dependencies
import express from 'express';

// local dependencies
import { validate } from '../middlewares/index.js';
import { login, register, logout, loginValidator, registerValidator, logoutValidator, refreshAccessToken, getMe, requireAuth } from '../controllers/auth.js';

const router = express.Router();

router.post('/logout', logoutValidator, logout);
router.post('/login', loginValidator, validate, login);
router.post('/refresh', logoutValidator, refreshAccessToken);
router.post('/register', registerValidator, validate, register);
router.get('/me', requireAuth, getMe);

export default router;
