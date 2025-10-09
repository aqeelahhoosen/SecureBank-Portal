const express = require('express');
const { createPayment, getUserPayments, getPendingPayments, verifyPayment } = require('../controllers/paymentController');
const { paymentValidation, handleValidationErrors } = require('../middleware/validation');
const auth = require('../middleware/auth');

const router = express.Router();

router.post('/', auth, paymentValidation, handleValidationErrors, createPayment);
router.get('/user', auth, getUserPayments);
router.get('/pending', auth, getPendingPayments);
router.post('/:id/verify', auth, verifyPayment);

module.exports = router;