const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    match: [/^[a-zA-Z\s]{2,50}$/, 'Full name must contain only letters and spaces']
  },
  idNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^[a-zA-Z0-9]{6,20}$/, 'ID number must be 6-20 alphanumeric characters']
  },
  accountNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^[0-9]{10,15}$/, 'Account number must be 10-15 digits']
  },
  username: {
    type: String,
    required: true,
    unique: true,
    match: [/^[a-zA-Z0-9_]{3,20}$/, 'Username must be 3-20 alphanumeric characters']
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  }
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);