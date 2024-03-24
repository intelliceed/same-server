import mongoose from 'mongoose';
import { USER_ROLE } from '../constants/index.js';

const UserSchema = new mongoose.Schema({
  lastName: { type: String, required: true, min: 2, max: 50, trim: true },
  firstName: { type: String, required: true, min: 2, max: 50, trim: true },
  password: { type: String, required: true, min: 6, max: 24, select: false },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  subscribers: { type: [{ ref: 'User', type: mongoose.Schema.Types.ObjectId }], default: [] },
  role: { type: String, required: true, enum: Object.values(USER_ROLE), default: USER_ROLE.USER },
  picturePath: { type: String, default: null },
  viewedProfile: { type: Number },
  impressions: { type: Number },
  occupation: { type: String },
  location: { type: String },
}, { timestamps: true });

const UserModel = mongoose.model('User', UserSchema);

export default UserModel;
