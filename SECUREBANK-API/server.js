const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost', 'file://'],
  credentials: true
}));
app.use(express.json());

// MongoDB Connection with detailed logging
const connectDB = async () => {
  try {
    console.log('Attempting to connect to MongoDB...');
    
    // Remove password from log for security
    const safeUri = process.env.MONGODB_URI ? 
      process.env.MONGODB_URI.replace(/mongodb\+srv:\/\/([^:]+):([^@]+)@/, 'mongodb+srv://$1:****@') : 
      'Not configured';
    
    console.log('Connection URI:', safeUri);
    
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅MongoDB Connected Successfully');
    console.log('Database:', mongoose.connection.db.databaseName);
    return true;
    
  } catch (error) {
    console.error('❌ MongoDB connection failed:');
    console.error('   Error:', error.message);
    
    if (error.message.includes('bad auth')) {
      console.error('    Authentication failed - check username/password');
      console.error('    Tip: Make sure password is URL encoded if it contains special characters');
    } else if (error.message.includes('getaddrinfo')) {
      console.error('   🌐 Network error - check cluster URL and internet connection');
    }
    
    console.log('Starting in MOCK MODE - Data will reset on server restart');
    return false;
  }
};

// Database connection state
let dbConnected = false;

// Initialize database connection
(async () => {
  dbConnected = await connectDB();
})();

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  idNumber: { type: String, required: true, unique: true, trim: true },
  accountNumber: { type: String, required: true, unique: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 10000.00 }
}, { timestamps: true });

const paymentSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  currency: { type: String, required: true, enum: ['USD', 'EUR', 'GBP'] },
  payeeAccountNumber: { type: String, required: true },
  swiftCode: { type: String, required: true },
  beneficiaryName: { type: String, required: true },
  beneficiaryBank: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['Pending', 'Completed', 'Failed'], default: 'Pending' },
  reference: { type: String, unique: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Payment = mongoose.model('Payment', paymentSchema);

// Mock data fallback
let mockUsers = [];
let mockPayments = [];

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'API is running',
    database: dbConnected ? 'MongoDB Connected' : 'Mock Mode - No Database',
    timestamp: new Date().toISOString()
  });
});

// POST /register
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, idNumber, accountNumber, username, password } = req.body;

    if (!fullName || !idNumber || !accountNumber || !username || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    if (dbConnected) {
      // Database registration
      const existingUser = await User.findOne({
        $or: [{ username }, { idNumber }, { accountNumber }]
      });

      if (existingUser) {
        return res.status(400).json({ success: false, message: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ fullName, idNumber, accountNumber, username, password: hashedPassword });
      await user.save();

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

      return res.status(201).json({
        success: true,
        message: 'Registration successful (Database)',
        data: { token, user: { id: user._id, username: user.username, fullName: user.fullName, accountNumber: user.accountNumber, balance: user.balance } }
      });
    } else {
      // Mock registration
      const existingUser = mockUsers.find(u => u.username === username || u.idNumber === idNumber || u.accountNumber === accountNumber);
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'User already exists' });
      }

      const user = { _id: Date.now().toString(), fullName, idNumber, accountNumber, username, password, balance: 10000, createdAt: new Date() };
      mockUsers.push(user);

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

      return res.status(201).json({
        success: true,
        message: 'Registration successful (Mock Mode)',
        data: { token, user: { id: user._id, username: user.username, fullName: user.fullName, accountNumber: user.accountNumber, balance: user.balance } }
      });
    }

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Error during registration' });
  }
});

// POST /login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    if (dbConnected) {
      const user = await User.findOne({ username });
      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

      return res.json({
        success: true,
        message: 'Login successful (Database)',
        data: { token, user: { id: user._id, username: user.username, fullName: user.fullName, accountNumber: user.accountNumber, balance: user.balance } }
      });
    } else {
      const user = mockUsers.find(u => u.username === username);
      if (!user || user.password !== password) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

      return res.json({
        success: true,
        message: 'Login successful (Mock Mode)',
        data: { token, user: { id: user._id, username: user.username, fullName: user.fullName, accountNumber: user.accountNumber, balance: user.balance } }
      });
    }

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Error during login' });
  }
});

const PORT = process.env.PORT || 7000;
app.listen(PORT, () => {
  console.log(` Secure Bank API running on port ${PORT}`);
  console.log(` Mode: ${dbConnected ? 'DATABASE' : 'MOCK DATA'}`);
  console.log(`🔗 Health: http://localhost:${PORT}/api/health`);
});