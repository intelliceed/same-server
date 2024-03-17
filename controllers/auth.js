// outsource dependencies
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { body } from 'express-validator';
import { StatusCodes } from 'http-status-codes';

// local dependencies
import UserModel from '../models/User.js';
import TokenModel from '../models/Token.js';
import { TOKEN_TYPE } from '../constants/index.js';

export const requireAuth = async (req, res, next) => {
  try {
    const accessToken = req.header('Authorization').replace('Bearer ', '');

    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    const token = await TokenModel.findOne({ session: decoded.sid, user: decoded.id, type: TOKEN_TYPE.ACCESS, value: accessToken }).exec();
    if (!token) { throw new Error('unauthorized'); }

    // Attach authenticated user and Access Token to request object
    req.authData = { userId: decoded.id, token: accessToken, tokenId: decoded.sid };
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

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email }).select('password').exec();
    if (!user) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'Invalid credentials', errorCode: 'invalid_credentials' }); }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) { return res.status(StatusCodes.NOT_FOUND).json({ message: 'Invalid credentials', errorCode: 'invalid_credentials' }); }
    const sid = uuidv4();
    const accessToken = jwt.sign({
      sid,
      id: user._id,
      email: user.email,
      type: TOKEN_TYPE.ACCESS,
      lastName: user.lastName,
      firstName: user.firstName,
    }, process.env.JWT_ACCESS_SECRET, { expiresIn: Number(process.env.JWT_ACCESS_LIFETIME || 3600) });
    const decodedAccessToken = jwt.decode(accessToken);
    const accessTokenDoc = await new TokenModel({
      session: sid,
      user: user._id,
      value: accessToken,
      type: TOKEN_TYPE.ACCESS,
      expires: new Date(decodedAccessToken.exp * 1e3),
    }).save();

    const refreshToken = jwt.sign({ sid, id: user._id, type: 'refresh' }, process.env.JWT_REFRESH_SECRET, { expiresIn: Number(process.env.JWT_REFRESH_LIFETIME || 86400) });
    const decodedRefreshToken = jwt.decode(refreshToken);
    const refreshTokenDoc = await new TokenModel({
      session: sid,
      user: user._id,
      value: refreshToken,
      type: TOKEN_TYPE.REFRESH,
      expires: new Date(decodedRefreshToken.exp * 1e3),
    }).save();

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
    const accessToken = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET, { ignoreExpiration: true });
    const { refreshToken } = req.body;
    const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, { ignoreExpiration: true });
    await TokenModel.deleteMany({ $and: [{ user: decoded.id }], $or: [{ session: decodedRefresh.sid }] }).exec();

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
    const expiredAccessToken = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(expiredAccessToken, process.env.JWT_ACCESS_SECRET, { ignoreExpiration: true });
    const { refreshToken } = req.body;
    try {
      const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      if ((decoded.id !== decodedRefresh.id) || (decoded.sid !== decodedRefresh.sid)) { throw new Error('invalid-refresh-or-access-token'); }
      await deleteUserExpiredTokens(decodedRefresh.id);
      const refreshTokenDoc = await TokenModel.findOne({
        sid: decodedRefresh.sid,
        user: decodedRefresh.id,
        type: TOKEN_TYPE.REFRESH,
      }).exec();
      if (!refreshTokenDoc) { throw new Error('invalid-refresh-token'); }
      const user = await UserModel.findById(decodedRefresh.id).exec();
      const accessToken = jwt.sign({
        id: user._id,
        email: user.email,
        type: TOKEN_TYPE.ACCESS,
        lastName: user.lastName,
        firstName: user.firstName,
        sid: refreshTokenDoc.session,
      }, process.env.JWT_ACCESS_SECRET, { expiresIn: Number(process.env.JWT_ACCESS_LIFETIME || 3600) });
      const accessTokenDoc = await new TokenModel({
        user: user._id,
        type: TOKEN_TYPE.ACCESS,
        session: refreshTokenDoc.session,
        expires: new Date(accessToken.exp),
      }).save();
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
    const user = await UserModel.findById(req.authData?.userId).exec();
    return res.status(StatusCodes.OK).json(user);
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error });
  }
};
