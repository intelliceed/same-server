// outsource dependencies
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { StatusCodes } from 'http-status-codes';
import { body, validationResult } from 'express-validator';

// local dependencies
import UserModel from '../models/User.js';
import TokenModel from '../models/Token.js';
import { TOKEN_TYPE } from '../constants/index.js';

export const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
    }
    const accessToken = authHeader.replace('Bearer ', '');

    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    const token = await TokenModel.findOne({ _id: decoded.tid, user: decoded.id, type: TOKEN_TYPE.ACCESS }).exec();
    if (!token) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
    }
    // Attach authenticated user and Access Token to request object
    req.userId = decoded.id;
    req.token = accessToken;
    req.tokenId = decoded.tid;
    next();
  } catch (error) {
    return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
  }
};

export const registerValidator = [
  body('firstName')
    .trim()
    .notEmpty()
    .withMessage('firstName field is required'),
  body('lastName')
    .trim()
    .notEmpty()
    .withMessage('lastName field is required'),
  body('email')
    .trim()
    .notEmpty()
    .withMessage('email field is required')
    .bail()
    .isEmail()
    .withMessage('email is invalid')
    .bail(),
  // .custom(async (email) => {
  //   // Finding if email exists in Database
  //   const emailExists = await UserModel.findOne({ email });
  //   if (emailExists) {
  //     throw new Error('E-mail already in use');
  //   }
  // }),
  body('password')
    .notEmpty()
    .withMessage('password field is required')
    .bail()
    .isLength({ min: 8 })
    .withMessage('Password MUST be at least 8 characters long'),
];

export const register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ errors: errors.array(), errorCode: 'validation_failed', message: errors.array()[0]?.msg });
    }
    const { firstName, lastName, password, email, occupation } = req.body;
    const existingUser = await UserModel.findOne({ email }).exec();
    if (existingUser) {
      return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ message: 'User with such email already exist', errorCode: 'user_already_exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = await new UserModel({ firstName, lastName, password: passwordHash, email, occupation }).save();

    return res.status(StatusCodes.CREATED).json({ ...newUser, password: undefined });
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
  }
};

export const loginValidator = [
  body('email')
    .trim()
    .notEmpty()
    .withMessage('email field is required')
    .bail()
    .isEmail()
    .withMessage('email is invalid'),
  body('password').trim().notEmpty().withMessage('password field is required'),
];

const deleteUserExpiredTokens = async userId => {
  try {
    await TokenModel.deleteMany({ user: userId, expires: { $lt: new Date() } });
  } catch (error) {
    console.info(error);
  }
};

const generateAccessToken = async user => {
  const accessTokenExp = Math.floor(Date.now() / 1e3) + Number(process.env.JWT_ACCESS_LIFETIME || 3600);
  const accessTokenDoc = await new TokenModel({
    user: user._id,
    type: TOKEN_TYPE.ACCESS,
    expires: new Date(accessTokenExp * 1e3),
  }).save();
  return jwt.sign({
    id: user._id,
    type: 'access',
    email: user.email,
    exp: accessTokenExp,
    tid: accessTokenDoc._id,
    lastName: user.lastName,
    firstName: user.firstName,
  }, process.env.JWT_ACCESS_SECRET);
};

export const login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ errors: errors.array(), errorCode: 'validation_failed', message: errors.array()[0]?.msg });
    }
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email }).select('password').exec();
    if (!user) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'Invalid credentials', errorCode: 'invalid_credentials' }); }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'Invalid credentials', errorCode: 'invalid_credentials' }); }
    const accessToken = await generateAccessToken(user);

    const refreshTokenExp = Math.floor(Date.now() / 1e3) + Number(process.env.JWT_REFRESH_LIFETIME || 86400);
    const refreshTokenDoc = await new TokenModel({
      user: user._id,
      type: TOKEN_TYPE.REFRESH,
      expires: new Date(refreshTokenExp * 1e3),
    }).save();
    const refreshToken = jwt.sign({ tid: refreshTokenDoc._id, id: user._id, type: 'refresh', exp: refreshTokenExp }, process.env.JWT_REFRESH_SECRET);

    await deleteUserExpiredTokens(user._id);

    return res.status(StatusCodes.OK).json({ accessToken, refreshToken });
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
  }
};

export const logoutValidator = [
  body('refreshToken')
    .trim()
    .notEmpty()
    .withMessage('refreshToken is required'),
];

export const logout = async (req, res) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
    }
    const accessToken = authHeader.replace('Bearer ', '');

    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET, { ignoreExpiration: true });
    const { refreshToken } = req.body;
    const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, { ignoreExpiration: true });
    await TokenModel.deleteMany({ $and: [{ user: decoded.id }], $or: [{ _id: decoded.tid }, { _id: decodedRefresh.tid }] }).exec();

    await deleteUserExpiredTokens(decoded.id);
    return res.status(StatusCodes.OK).json({ success: true });
  } catch (error) {
    if (error?.name !== 'JsonWebTokenError') {
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
    }
    return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
  }
};

export const refreshAccessToken = async (req, res) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
    }
    const expiredAccessToken = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(expiredAccessToken, process.env.JWT_ACCESS_SECRET, { ignoreExpiration: true });
    const { refreshToken } = req.body;
    try {
      const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      if (decoded.id !== decodedRefresh.id) { throw new Error('invalid-refresh-or-access-token'); }
      await deleteUserExpiredTokens(decodedRefresh.id);
      const isTokenExist = await TokenModel.exists({ _id: decodedRefresh.tid, user: decodedRefresh.id }).exec();
      if (!isTokenExist) { throw new Error('invalid-refresh-token'); }
      const user = await UserModel.findById(decodedRefresh.id).exec();
      const accessToken = await generateAccessToken(user);
      return res.status(StatusCodes.OK).json({ accessToken });
    } catch (error) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Authorization data is invalid', errorCode: 'unauthorized' });
    }
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
  }
};

export const getMe = async (req, res) => {
  try {
    const user = await UserModel.findById(req.userId).exec();
    return res.status(StatusCodes.OK).json(user);
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
  }
};
