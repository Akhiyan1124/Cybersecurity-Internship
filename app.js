// server.js
const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();
app.use(express.json());
app.use(helmet());

// ================= LOGGER SETUP =================
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// ================= VARIABLES =================
const users = []; // Temporary in-memory storage
const SECRET_KEY = 'your-secret-key';

// ================= TEST ROUTE =================
app.get('/', (req, res) => {
  res.send('Server is running!');
});

// ================= SIGNUP ROUTE =================
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      logger.warn('Signup attempt with missing fields');
      return res.status(400).json({ error: 'Email and password required' });
    }

    if (!validator.isEmail(email)) {
      logger.warn(`Invalid email attempt: ${email}`);
      return res.status(400).json({ error: 'Invalid email' });
    }

    if (!validator.isStrongPassword(password)) {
      logger.warn(`Weak password attempt for: ${email}`);
      return res.status(400).json({ error: 'Password is not strong enough' });
    }

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      logger.warn(`Signup attempt for existing user: ${email}`);
      return res.status(400).json({ error: 'User already exists' });
    }

    // 🔒 Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length + 1,
      email,
      password: hashedPassword
    };

    users.push(newUser);
    logger.info(`New user registered: ${email}`);
    console.log("Saved User:", newUser);  // 👈 Check hashed password in terminal

    // Create JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token
    });

  } catch (error) {
    logger.error(`Signup error: ${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================= LOGIN ROUTE =================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);

    if (!user) {
      logger.warn(`Login failed - user not found: ${email}`);
      return res.status(400).json({ error: 'User not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      logger.warn(`Invalid password attempt for: ${email}`);
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    logger.info(`User logged in: ${email}`);

    res.json({
      message: 'Login successful',
      token
    });

  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================= JWT MIDDLEWARE =================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}

// ================= PROTECTED ROUTE =================
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({
    message: `Welcome to your dashboard, ${req.user.email}!`,
    userId: req.user.id
  });
});

// ================= START SERVER =================
app.listen(3000, () => {
  logger.info('Server running on http://localhost:3000');
});