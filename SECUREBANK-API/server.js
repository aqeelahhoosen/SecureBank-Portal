const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const expressBrute = require('express-brute');
const MongoStore = require('express-brute-mongo');
require('dotenv').config();

const app = express();

// ======================
// SECURITY MIDDLEWARE CONFIGURATION
// ======================

// 1. Helmet - Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false // Disable for CDN resources
}));

// 2. CORS Configuration
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost', 'file://'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// 3. Rate Limiting - Prevent brute force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all requests
app.use(limiter);

// 4. Bruteforce protection for login/register
const store = new MongoStore((ready) => {
  ready(mongoose.connection.db);
});

const bruteforce = new expressBrute(store, {
  freeRetries: 3, // 3 free attempts
  minWait: 5 * 60 * 1000, // 5 minutes
  maxWait: 60 * 60 * 1000, // 1 hour
  lifetime: 24 * 60 * 60, // 1 day
  failCallback: (req, res, next, nextValidRequestDate) => {
    res.status(429).json({
      success: false,
      message: `Too many failed attempts. Please try again after ${Math.round((nextValidRequestDate - Date.now()) / 60000)} minutes.`
    });
  }
});

// 5. Body parsing security
app.use(express.json({ 
  limit: '10kb' // Prevent large payload attacks
}));

// 6. Data sanitization against NoSQL injection
app.use(mongoSanitize());

// 7. Data sanitization against XSS
app.use(xss());

// 8. Prevent parameter pollution
app.use(hpp({
  whitelist: ['amount', 'currency'] // Allow duplicate parameters for these fields
}));

// ======================
// INPUT WHITELISTING PATTERNS
// ======================

const VALIDATION_PATTERNS = {
  username: /^[a-zA-Z0-9_]{3,20}$/,
  idNumber: /^[A-Z0-9]{6,20}$/,
  accountNumber: /^\d{10,15}$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  fullName: /^[a-zA-Z\s]{2,50}$/,
  swiftCode: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,
  beneficiaryName: /^[a-zA-Z\s\.\-]{2,100}$/,
  bankName: /^[a-zA-Z0-9\s\.\-&]{2,100}$/,
  amount: /^\d+(\.\d{1,2})?$/,
  currency: /^(USD|EUR|GBP|JPY|CAD|AUD|CHF)$/
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/['"\\]/g, '')
    .trim()
    .substring(0, 255);
};

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

// ======================
// MONGODB CONNECTION
// ======================

const connectDB = async () => {
  try {
    console.log('🔗 Attempting to connect to MongoDB...');
    
    const safeUri = process.env.MONGODB_URI ? 
      process.env.MONGODB_URI.replace(/mongodb\+srv:\/\/([^:]+):([^@]+)@/, 'mongodb+srv://$1:****@') : 
      'Not configured';
    
    console.log('📡 Connection URI:', safeUri);
    
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ MongoDB Connected Successfully');
    console.log('📊 Database:', mongoose.connection.db.databaseName);
    return true;
    
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    console.log('🔄 Starting in MOCK MODE - Data will reset on server restart');
    return false;
  }
};

let dbConnected = false;
(async () => {
  dbConnected = await connectDB();
})();

// ======================
// DATABASE SCHEMAS
// ======================

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  idNumber: { type: String, required: true, unique: true, trim: true },
  accountNumber: { type: String, required: true, unique: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 10000.00 },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date }
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

// ======================
// MOCK DATA FALLBACK
// ======================

let mockUsers = [];
let mockPayments = [];

// ======================
// JWT AUTHENTICATION
// ======================

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

// ======================
// ROUTES WITH SECURITY
// ======================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'API is running',
    database: dbConnected ? 'MongoDB Connected' : 'Mock Mode - No Database',
    security: 'Helmet, Rate Limiting, Brute Force Protection Active',
    timestamp: new Date().toISOString()
  });
});

// POST /register - With bruteforce protection
app.post('/api/register', bruteforce.prevent, async (req, res) => {
  console.log('👤 [Register] Request received with security middleware');
  
  try {
    const fullNameValidation = validateInput('Full Name', req.body.fullName, 'fullName');
    const idNumberValidation = validateInput('ID Number', req.body.idNumber, 'idNumber');
    const accountNumberValidation = validateInput('Account Number', req.body.accountNumber, 'accountNumber');
    const usernameValidation = validateInput('Username', req.body.username, 'username');
    const passwordValidation = validateInput('Password', req.body.password, 'password');

    const validations = [fullNameValidation, idNumberValidation, accountNumberValidation, usernameValidation, passwordValidation];
    const failedValidation = validations.find(v => !v.isValid);
    
    if (failedValidation) {
      return res.status(400).json({ 
        success: false, 
        message: failedValidation.message 
      });
    }

    const { value: fullName } = fullNameValidation;
    const { value: idNumber } = idNumberValidation;
    const { value: accountNumber } = accountNumberValidation;
    const { value: username } = usernameValidation;
    const { value: password } = passwordValidation;

    if (dbConnected) {
      const existingUser = await User.findOne({
        $or: [{ username }, { idNumber }, { accountNumber }]
      });

      if (existingUser) {
        return res.status(400).json({ 
          success: false, 
          message: 'User already exists with these credentials' 
        });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ 
        fullName, 
        idNumber, 
        accountNumber, 
        username, 
        password: hashedPassword 
      });

      await user.save();

      const token = jwt.sign(
        { 
          userId: user._id, 
          username: user.username 
        }, 
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
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
      const existingUser = mockUsers.find(u => 
        u.username === username || u.idNumber === idNumber || u.accountNumber === accountNumber
      );
      
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = { 
        _id: Date.now().toString(), 
        fullName, 
        idNumber, 
        accountNumber, 
        username, 
        password: hashedPassword,
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
    console.error('💥 [Register] ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed: ' + error.message 
    });
  }
});

// POST /login - With bruteforce protection
app.post('/api/login', bruteforce.getMiddleware({
  key: (req, res, next) => {
    next(req.body.username);
  }
}), async (req, res) => {
  console.log('🔐 [Login] Request received with bruteforce protection');
  
  try {
    const usernameValidation = validateInput('Username', req.body.username, 'username');
    const passwordValidation = validateInput('Password', req.body.password, 'password', false);

    const validations = [usernameValidation, passwordValidation];
    const failedValidation = validations.find(v => !v.isValid);
    
    if (failedValidation) {
      return res.status(400).json({ 
        success: false, 
        message: failedValidation.message 
      });
    }

    const { value: username } = usernameValidation;
    const { value: password } = passwordValidation;

    if (dbConnected) {
      const user = await User.findOne({ username });
      
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (!isPasswordValid) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

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
      const user = mockUsers.find(u => u.username === username);
      
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

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
    console.error('💥 [Login] ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Login failed: ' + error.message 
    });
  }
});

// Payment routes (protected)
app.post('/api/payments', authenticateToken, async (req, res) => {
  // ... (your existing payment code with validation)
});

app.get('/api/payments', authenticateToken, async (req, res) => {
  // ... (your existing payments code)
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
  // ... (your existing profile code)
});

// ======================
// ERROR HANDLING MIDDLEWARE
// ======================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('🚨 Global Error Handler:', error);
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

const PORT = process.env.PORT || 7000;
app.listen(PORT, () => {
  console.log(`\n🎉 ======= SECURE BANK API STARTED =======`);
  console.log(`🚀 Secure Bank API running on port ${PORT}`);
  console.log(`📊 Database Mode: ${dbConnected ? 'MongoDB CONNECTED' : 'MOCK DATA (No DB)'}`);
  console.log(`🛡️  SECURITY MIDDLEWARE ACTIVE:`);
  console.log(`   ✅ Helmet - Security headers`);
  console.log(`   ✅ Rate Limiting - 100 req/15min per IP`);
  console.log(`   ✅ Express Brute - Bruteforce protection`);
  console.log(`   ✅ Mongo Sanitize - NoSQL injection protection`);
  console.log(`   ✅ XSS Clean - Cross-site scripting protection`);
  console.log(`   ✅ HPP - Parameter pollution protection`);
  console.log(`   ✅ CORS - Cross-origin resource sharing`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
  console.log('============================================\n');
});