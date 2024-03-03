// outsource dependencies
import express from 'express';

// local dependencies
import { login, register, logout, loginValidator, registerValidator, logoutValidator } from '../controllers/auth.js';

const router = express.Router();

router.post('/register', registerValidator, register);
router.post('/logout', logoutValidator, logout);
router.post('/login', loginValidator, login);

export default router;
