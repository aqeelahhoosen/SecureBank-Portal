const express = require('express');
const { register, login, getMe } = require('../controllers/authController');
const { registerValidation, loginValidation, handleValidationErrors } = require('../middleware/validation');
const auth = require('../middleware/auth');

const router = express.Router();

router.post('/register', registerValidation, handleValidationErrors, register);
router.post('/login', loginValidation, handleValidationErrors, login);
router.get('/me', auth, getMe);

module.exports = router;