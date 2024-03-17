// outsource dependencies
import { StatusCodes, ReasonPhrases } from 'http-status-codes';
import { validationResult } from 'express-validator';

export const validate = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ errors: errors.array(), errorCode: 'validation_failed', message: errors.array()[0]?.msg });
    }
    next();
  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      error,
      message: ReasonPhrases.INTERNAL_SERVER_ERROR,
      errorCode: ReasonPhrases.INTERNAL_SERVER_ERROR,
    });
  }
};
