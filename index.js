// outsource dependencies
import cors from 'cors';
import path from 'path';
import dotenv from 'dotenv';
import multer from 'multer';
import helmet from 'helmet';
import morgan from 'morgan';
import express from 'express';
import mongoose from 'mongoose';
import { fileURLToPath } from 'url';
import bodyParser from 'body-parser';

// configuration
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(express.json());
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: 'cross-origin' }));
app.use(morgan('common'));
app.use(bodyParser.json({ limit: '30mb' }));
app.use(bodyParser.urlencoded({ limit: '30mb', extended: true }));
app.use(cors());
app.use('/assets', express.static(path.join(__dirname, 'public/assets')));

// storage
const storage = multer.diskStorage({
  destination (req, file, cb) {
    cb(null, 'public/assets');
  },
  filename (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });

// MONGO SETUP
const PORT = process.env.PORT || 3001;

mongoose.connect(process.env.MONGO_URL).then(() => {
  app.listen(PORT, () => console.log(`Server is running on PORT: ${PORT}`));
}).catch(error => console.log('Failed to connect:', error));
