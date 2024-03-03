// outsource dependencies
import mongoose from 'mongoose';

// local dependencies
import { TOKEN_TYPE } from '../constants/index.js';

const TokenSchema = new mongoose.Schema({
  expires: { type: Date },
  value: { type: String },
  type: { type: String, required: true, enum: Object.values(TOKEN_TYPE) },
  user: { ref: 'User', required: true, type: mongoose.Schema.Types.ObjectId },
}, { timestamps: true });

const TokenModel = mongoose.model('Token', TokenSchema);

export default TokenModel;
