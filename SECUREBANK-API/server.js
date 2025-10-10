const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

//Security Configuration 

//Whitelisting Patterns 
const VALIDATION_PATTERNS = {
  username: /^[a-zA-Z0-9_]{3,20}$/, // 3-20 chars, letters, numbers, underscore only
  idNumber: /^[A-Z0-9]{6,20}$/, // 6-20 chars, uppercase letters and numbers only
  accountNumber: /^\d{10,15}$/, // 10-15 digits only
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, // Min 8 chars, 1 upper, 1 lower, 1 number, 1 special
  fullName: /^[a-zA-Z\s]{2,50}$/, // 2-50 letters and spaces only
  swiftCode: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/, // Standard SWIFT/BIC format
  beneficiaryName: /^[a-zA-Z\s\.\-]{2,100}$/, // Letters, spaces, dots, hyphens only
  bankName: /^[a-zA-Z0-9\s\.\-&]{2,100}$/, // Letters, numbers, spaces, common symbols
  amount: /^\d+(\.\d{1,2})?$/, // Positive numbers with optional 2 decimal places
  currency: /^(USD|EUR|GBP|JPY|CAD|AUD|CHF)$/ // Only allowed currencies
};

//Input Santization Function 
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Remove potentially dangerous characters
  return input
    .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .replace(/['"\\]/g, '') // Remove quotes and backslashes
    .trim() // Remove whitespace
    .substring(0, 255); // Limit length
};

//Enhanced validation function 
const validateInput = (field, value, patternName, isRequired = true) => {
  if (!value && isRequired) {
    return { isValid: false, message: `${field} is required` };
  }
  
  if (!value && !isRequired) {
    return { isValid: true, value: '' };
  }
  
  const sanitized = sanitizeInput(value.toString());
  
  if (patternName && VALIDATION_PATTERNS[patternName]) {
    if (!VALIDATION_PATTERNS[patternName].test(sanitized)) {
      return { 
        isValid: false, 
        message: `Invalid ${field} format` 
      };
    }
  }
  
  return { isValid: true, value: sanitized };
};

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


//JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};



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
  console.log('👤 [Register] Request received with whitelisting validation');
  
  try {
    // Input validation with whitelisting
    const fullNameValidation = validateInput('Full Name', req.body.fullName, 'fullName');
    const idNumberValidation = validateInput('ID Number', req.body.idNumber, 'idNumber');
    const accountNumberValidation = validateInput('Account Number', req.body.accountNumber, 'accountNumber');
    const usernameValidation = validateInput('Username', req.body.username, 'username');
    const passwordValidation = validateInput('Password', req.body.password, 'password');

    // Check if any validation failed
    const validations = [fullNameValidation, idNumberValidation, accountNumberValidation, usernameValidation, passwordValidation];
    const failedValidation = validations.find(v => !v.isValid);
    
    if (failedValidation) {
      console.log('❌ [Register] Input validation failed:', failedValidation.message);
      return res.status(400).json({ 
        success: false, 
        message: failedValidation.message 
      });
    }

    // Use sanitized values
    const { value: fullName } = fullNameValidation;
    const { value: idNumber } = idNumberValidation;
    const { value: accountNumber } = accountNumberValidation;
    const { value: username } = usernameValidation;
    const { value: password } = passwordValidation;

    console.log('✅ [Register] All inputs validated and sanitized:', {
      fullName: fullName.substring(0, 20) + '...',
      idNumber: idNumber.substring(0, 6) + '...', 
      accountNumber: accountNumber.substring(0, 6) + '...',
      username: username,
      password: '***' // Don't log password
    });

    if (dbConnected) {
      console.log('🗄️ [Register] Using DATABASE mode');
      
      // Check for existing user with sanitized inputs
      const existingUser = await User.findOne({
        $or: [{ username }, { idNumber }, { accountNumber }]
      });

      if (existingUser) {
        console.log('❌ [Register] User already exists');
        return res.status(400).json({ 
          success: false, 
          message: 'User already exists with these credentials' 
        });
      }

      console.log('✅ [Register] No existing user found');

      // 🔐 PASSWORD HASHING WITH SALTING
      console.log('🔐 [Register] Hashing password with bcrypt (12 rounds)...');
      const hashedPassword = await bcrypt.hash(password, 12);
      console.log('✅ [Register] Password hashed successfully');

      // Create user with sanitized data
      const user = new User({ 
        fullName, 
        idNumber, 
        accountNumber, 
        username, 
        password: hashedPassword 
      });

      await user.save();
      console.log('💾 [Register] User saved to database, ID:', user._id);

      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: user._id, 
          username: user.username 
        }, 
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      console.log('✅ [Register] Registration COMPLETED successfully');
      
      return res.status(201).json({
        success: true,
        message: 'Registration successful',
        data: { 
          token, 
          user: { 
            id: user._id, 
            username: user.username, 
            fullName: user.fullName, 
            accountNumber: user.accountNumber, 
            balance: user.balance 
          } 
        }
      });
    } else {
      // Mock mode with validation
      console.log('🔄 [Register] Using MOCK mode with validation');
      
      const existingUser = mockUsers.find(u => 
        u.username === username || u.idNumber === idNumber || u.accountNumber === accountNumber
      );
      
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'User already exists' });
      }

      // In mock mode, we still hash the password for consistency
      const hashedPassword = await bcrypt.hash(password, 12);
      
      const user = { 
        _id: Date.now().toString(), 
        fullName, 
        idNumber, 
        accountNumber, 
        username, 
        password: hashedPassword, // Store hashed even in mock
        balance: 10000, 
        createdAt: new Date() 
      };
      
      mockUsers.push(user);

      const token = jwt.sign(
        { userId: user._id, username: user.username }, 
        process.env.JWT_SECRET, 
        { expiresIn: '24h' }
      );

      return res.status(201).json({
        success: true,
        message: 'Registration successful (Mock Mode)',
        data: { token, user: { id: user._id, username: user.username, fullName: user.fullName, accountNumber: user.accountNumber, balance: user.balance } }
      });
    }

  } catch (error) {
    console.error('💥 [Register] UNEXPECTED ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed: ' + error.message 
    });
  }
});

// POST /login - WITH WHITELISTING
app.post('/api/login', async (req, res) => {
  console.log('🔐 [Login] Request received with whitelisting validation');
  
  try {
    // Input validation with whitelisting
    const usernameValidation = validateInput('Username', req.body.username, 'username');
    const passwordValidation = validateInput('Password', req.body.password, 'password', false); // Password might be empty for validation

    // Check if any validation failed
    const validations = [usernameValidation, passwordValidation];
    const failedValidation = validations.find(v => !v.isValid);
    
    if (failedValidation) {
      console.log('❌ [Login] Input validation failed:', failedValidation.message);
      return res.status(400).json({ 
        success: false, 
        message: failedValidation.message 
      });
    }

    // Use sanitized values
    const { value: username } = usernameValidation;
    const { value: password } = passwordValidation;

    console.log('✅ [Login] Inputs validated and sanitized');

    if (dbConnected) {
      console.log('🗄️ [Login] Using DATABASE mode');
      
      const user = await User.findOne({ username });
      console.log('🔍 [Login] Database lookup result:', user ? 'User found' : 'User not found');
      
      if (!user) {
        console.log('❌ [Login] User not found in database:', username);
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      console.log('🔐 [Login] Password validation:', isPasswordValid ? 'VALID' : 'INVALID');
      
      if (!isPasswordValid) {
        console.log('❌ [Login] Invalid password for user:', username);
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
      console.log('✅ [Login] Login successful, token generated');

      return res.json({
        success: true,
        message: 'Login successful',
        data: { 
          token, 
          user: { 
            id: user._id, 
            username: user.username, 
            fullName: user.fullName, 
            accountNumber: user.accountNumber, 
            balance: user.balance 
          } 
        }
      });
    } else {
      console.log('🔄 [Login] Using MOCK mode');
      
      const user = mockUsers.find(u => u.username === username);
      console.log('🔍 [Login] Mock lookup result:', user ? 'User found' : 'User not found');
      
      if (!user) {
        console.log('❌ [Login] User not found in mock data');
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      // In mock mode, compare with hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        console.log('❌ [Login] Invalid password in mock data');
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });
      console.log('✅ [Login] Mock login successful');

      return res.json({
        success: true,
        message: 'Login successful (Mock Mode)',
        data: { 
          token, 
          user: { 
            id: user._id, 
            username: user.username, 
            fullName: user.fullName, 
            accountNumber: user.accountNumber, 
            balance: user.balance 
          } 
        }
      });
    }

  } catch (error) {
    console.error('💥 [Login] UNEXPECTED ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Login failed: ' + error.message 
    });
  }
});

// POST /payments - WITH WHITELISTING
app.post('/api/payments', authenticateToken, async (req, res) => {
  console.log('💰 [Payment] Request received with whitelisting validation');
  
  try {
    // Input validation with whitelisting
    const amountValidation = validateInput('Amount', req.body.amount?.toString(), 'amount');
    const currencyValidation = validateInput('Currency', req.body.currency, 'currency');
    const payeeAccountValidation = validateInput('Payee Account', req.body.payeeAccountNumber, 'accountNumber');
    const swiftCodeValidation = validateInput('SWIFT Code', req.body.swiftCode, 'swiftCode');
    const beneficiaryNameValidation = validateInput('Beneficiary Name', req.body.beneficiaryName, 'beneficiaryName');
    const beneficiaryBankValidation = validateInput('Beneficiary Bank', req.body.beneficiaryBank, 'bankName');

    // Check if any validation failed
    const validations = [amountValidation, currencyValidation, payeeAccountValidation, swiftCodeValidation, beneficiaryNameValidation, beneficiaryBankValidation];
    const failedValidation = validations.find(v => !v.isValid);
    
    if (failedValidation) {
      console.log('❌ [Payment] Input validation failed:', failedValidation.message);
      return res.status(400).json({
        success: false,
        message: failedValidation.message
      });
    }

    // Use sanitized values
    const amount = parseFloat(amountValidation.value);
    const { value: currency } = currencyValidation;
    const { value: payeeAccountNumber } = payeeAccountValidation;
    const { value: swiftCode } = swiftCodeValidation;
    const { value: beneficiaryName } = beneficiaryNameValidation;
    const { value: beneficiaryBank } = beneficiaryBankValidation;

    console.log('✅ [Payment] All payment inputs validated and sanitized');

    // Find user
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check balance
    if (user.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    // Generate unique reference
    const reference = 'SB' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();

    if (dbConnected) {
      // Create payment in database
      const payment = new Payment({
        amount,
        currency,
        payeeAccountNumber,
        swiftCode,
        beneficiaryName,
        beneficiaryBank,
        userId: user._id,
        reference,
        status: 'Processing'
      });

      await payment.save();

      // Update user balance
      user.balance -= amount;
      await user.save();

      console.log('✅ [Payment] Payment created successfully, reference:', reference);

      // Simulate payment processing
      setTimeout(async () => {
        try {
          const completedPayment = await Payment.findById(payment._id);
          if (completedPayment) {
            completedPayment.status = 'Completed';
            await completedPayment.save();
            console.log(`✅ [Payment] Payment ${reference} completed successfully`);
          }
        } catch (error) {
          console.error('❌ [Payment] Error updating payment status:', error);
        }
      }, 3000);

      return res.status(201).json({
        success: true,
        message: 'Payment created successfully and is being processed',
        data: {
          payment: {
            id: payment._id,
            amount: payment.amount,
            currency: payment.currency,
            payeeAccountNumber: payment.payeeAccountNumber,
            swiftCode: payment.swiftCode,
            beneficiaryName: payment.beneficiaryName,
            beneficiaryBank: payment.beneficiaryBank,
            status: payment.status,
            reference: payment.reference,
            createdAt: payment.createdAt
          },
          newBalance: user.balance
        }
      });
    } else {
      // Mock payment
      const payment = {
        _id: Date.now().toString(),
        amount,
        currency,
        payeeAccountNumber,
        swiftCode,
        beneficiaryName,
        beneficiaryBank,
        userId: user._id,
        reference,
        status: 'Processing',
        createdAt: new Date()
      };

      mockPayments.push(payment);

      // Update mock user balance
      user.balance -= amount;

      return res.status(201).json({
        success: true,
        message: 'Payment created successfully (Mock Mode)',
        data: {
          payment,
          newBalance: user.balance
        }
      });
    }

  } catch (error) {
    console.error('💥 [Payment] UNEXPECTED ERROR:', error);
    res.status(500).json({
      success: false,
      message: 'Payment processing failed: ' + error.message
    });
  }
});

// GET /payments - Get user payments
app.get('/api/payments', authenticateToken, async (req, res) => {
  try {
    if (dbConnected) {
      const payments = await Payment.find({ userId: req.user.userId }).sort({ createdAt: -1 });
      return res.json({
        success: true,
        data: { payments }
      });
    } else {
      const payments = mockPayments.filter(p => p.userId === req.user.userId);
      return res.json({
        success: true,
        data: { payments }
      });
    }
  } catch (error) {
    console.error('Get payments error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving payments'
    });
  }
});

// GET /user/profile - Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    if (dbConnected) {
      const user = await User.findById(req.user.userId).select('-password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      return res.json({
        success: true,
        data: { user }
      });
    } else {
      const user = mockUsers.find(u => u._id === req.user.userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      return res.json({
        success: true,
        data: { user }
      });
    }
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving user profile'
    });
  }
});

const PORT = process.env.PORT || 7000;
app.listen(PORT, () => {
  console.log(`\n🎉 ======= SECURE BANK API STARTED =======`);
  console.log(`🚀 Secure Bank API running on port ${PORT}`);
  console.log(`📊 Database Mode: ${dbConnected ? 'MongoDB CONNECTED' : 'MOCK DATA (No DB)'}`);
  console.log(`🛡️  Security: Whitelisting & Input Validation ACTIVE`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`✅ Endpoints protected with whitelisting:`);
  console.log(`   POST /api/register → User registration`);
  console.log(`   POST /api/login → User authentication`);
  console.log(`   POST /api/payments → Create payments`);
  console.log(`   GET /api/payments → Get user payments`);
  console.log(`   GET /api/user/profile → Get user profile`);
  console.log('============================================\n');
});