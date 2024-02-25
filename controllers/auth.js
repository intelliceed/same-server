// outsource dependencies
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { StatusCodes } from 'http-status-codes';

// local dependencies
import UserModel from '../models/User.js';

export const register = async (req, res) => {
  try {
    const { firstName, lastName, password, email, location, occupation } = req.body;
    const existingUser = await UserModel.findOne({ email }).exec();
    if (existingUser) { throw new Error('User with such email already exist'); }

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = await new UserModel({ firstName, lastName, password: passwordHash, email, location, occupation }).save();

    return res.status(StatusCodes.CREATED).json({ ...newUser, password: undefined });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error, message: error?.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email }).select('password');
    if (!user) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'User with such email and password doesn\'t exist' }); }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'User with such email and password doesn\'t exist' }); }
    return res.status(StatusCodes.OK).json({ accessToken: '', refreshToken: '' });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error, message: error });
  }
};
