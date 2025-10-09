const { body, validationResult } = require('express-validator');

const registerValidation = [
  body('fullName')
    .trim()
    .matches(/^[a-zA-Z\s]{2,50}$/)
    .withMessage('Full name must contain only letters and spaces (2-50 characters)'),
  
  body('idNumber')
    .trim()
    .matches(/^[a-zA-Z0-9]{6,20}$/)
    .withMessage('ID number must be 6-20 alphanumeric characters'),
  
  body('accountNumber')
    .trim()
    .matches(/^[0-9]{10,15}$/)
    .withMessage('Account number must be 10-15 digits'),
  
  body('username')
    .trim()
    .matches(/^[a-zA-Z0-9_]{3,20}$/)
    .withMessage('Username must be 3-20 alphanumeric characters or underscores'),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-zA-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one letter and one number')
];

const loginValidation = [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('accountNumber').trim().matches(/^[0-9]{10,15}$/).withMessage('Account number must be 10-15 digits'),
  body('password').notEmpty().withMessage('Password is required')
];

const paymentValidation = [
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be greater than 0'),
  body('currency').trim().matches(/^[A-Z]{3}$/).withMessage('Currency must be 3 uppercase letters'),
  body('payeeAccountNumber').trim().matches(/^[A-Za-z0-9]{8,34}$/).withMessage('Invalid account number format'),
  body('swiftCode').trim().matches(/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/).withMessage('Invalid SWIFT code format'),
  body('beneficiaryName').trim().matches(/^[a-zA-Z\s]{2,100}$/).withMessage('Beneficiary name must contain only letters and spaces')
];

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

module.exports = {
  registerValidation,
  loginValidation,
  paymentValidation,
  handleValidationErrors
};