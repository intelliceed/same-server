// outsource dependencies
import express from 'express';

// local dependencies
import { login, register } from '../controllers/auth.js';

const router = express.Router();

router.post('/login', login);
router.post('/register', register);

export default router;
