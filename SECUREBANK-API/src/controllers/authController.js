const jwt = require('jsonwebtoken');
const User = require('../models/User');

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

exports.register = async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { username: username },
        { idNumber: idNumber },
        { accountNumber: accountNumber }
      ]
    });

    if (existingUser) {
      let message = 'User already exists';
      if (existingUser.username === username) message = 'Username already taken';
      if (existingUser.idNumber === idNumber) message = 'ID number already registered';
      if (existingUser.accountNumber === accountNumber) message = 'Account number already registered';
      
      return res.status(400).json({
        success: false,
        message
      });
    }

    // Create new user
    const user = new User({
      fullName: fullName,
      idNumber: idNumber,
      accountNumber: accountNumber,
      username: username,
      password: password
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: {
        token,
        user: {
          id: user._id,
          username: user.username,
          fullName: user.fullName,
          accountNumber: user.accountNumber
        }
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Error during registration'
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { username, accountNumber, password } = req.body;

    // Find user
    const user = await User.findOne({
      username: username,
      accountNumber: accountNumber
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user._id,
          username: user.username,
          fullName: user.fullName,
          accountNumber: user.accountNumber
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Error during login'
    });
  }
};

exports.getMe = async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving user data'
    });
  }
};