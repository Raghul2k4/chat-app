const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const User = require('./model/user');

const app = express();
const PORT = 5000;
const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_KEY = process.env.REFRESH_KEY;

app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3001', // React App
  credentials: true
}));
app.use(express.json());

let refreshTokens = []; // FIXED: correct array variable

// MongoDB Connect
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// SIGNUP ROUTE
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(409).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN ROUTE
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id, username: user.username }, REFRESH_KEY, { expiresIn: '7d' });

    refreshTokens.push(refreshToken); // FIXED: proper array

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // FIXED: 7 days in ms
    });

    res.json({ token: accessToken });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// REFRESH TOKEN ROUTE
app.post('/api/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });
  if (!refreshTokens.includes(refreshToken)) return res.status(403).json({ error: 'Invalid refresh token' });

  jwt.verify(refreshToken, REFRESH_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid refresh token' });

    const newAccessToken = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '15m' });
    res.json({ token: newAccessToken });
  });
});

// LOGOUT ROUTE
app.post('/api/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out successfully' });
});

// VERIFY TOKEN MIDDLEWARE
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// PROTECTED ROUTE
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you accessed a protected route.` });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));