const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
  amount: {
    type: Number,
    required: true,
    min: 0.01
  },
  currency: {
    type: String,
    required: true,
    match: [/^[A-Z]{3}$/, 'Currency must be 3 uppercase letters']
  },
  payeeAccountNumber: {
    type: String,
    required: true,
    match: [/^[A-Za-z0-9]{8,34}$/, 'Invalid account number format']
  },
  swiftCode: {
    type: String,
    required: true,
    match: [/^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/, 'Invalid SWIFT code format']
  },
  beneficiaryName: {
    type: String,
    required: true,
    match: [/^[a-zA-Z\s]{2,100}$/, 'Beneficiary name must contain only letters and spaces']
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['Pending', 'Verified', 'Completed'],
    default: 'Pending'
  }
}, { timestamps: true });

module.exports = mongoose.model('Payment', paymentSchema);