import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true, min: 2, max: 50 },
  lastName: { type: String, required: true, min: 2, max: 50 },
  password: { type: String, required: true, min: 6, max: 24, select: false },
  email: { type: String, required: true, unique: true },
  picturePath: { type: String, default: null },
  friends: { type: Array, default: [] },
  location: { type: String },
  occupation: { type: String },
  impressions: { type: Number },
  viewedProfile: { type: Number },
}, { timestamps: true });

const UserModel = mongoose.model('User', UserSchema);

export default UserModel;
