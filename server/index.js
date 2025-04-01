// server.js
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// App and Server Setup
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Config
const JWT_SECRET = 'your_jwt_secret_key';

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/jwtChatDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Mongoose Schemas & Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  senderId: String,
  senderUsername: String,
  receiverId: String,
  receiverUsername: String,
  message: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// JWT Middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  });
}

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userExist = await User.findOne({ username });
    if (userExist) return res.status(400).json({ error: 'Username already taken' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, userId: user._id, username: user.username });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get All Users
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({}, { username: 1, _id: 1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get Chat History
app.get('/messages/:senderId/:receiverId', async (req, res) => {
  const { senderId, receiverId } = req.params;
  try {
    const messages = await Message.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId }
      ]
    }).sort({ timestamp: 1 });

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Example Protected Route
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed', userId: req.userId, username: req.username });
});

// Socket.IO One-to-One Chat
const users = {}; // { userId: { socketId, username } }

io.on('connection', (socket) => {
  console.log('🔌 New socket connected');

  socket.on('register user', ({ userId, username }) => {
    users[userId] = { socketId: socket.id, username };
    socket.userId = userId;
    socket.username = username;
    console.log(`✅ User registered: ${username} (${userId})`);
  });

  socket.on('private message', async ({ receiverId, message }) => {
    const senderId = socket.userId;
    const senderUsername = socket.username;

    try {
      const receiver = users[receiverId];
      if (receiver) {
        const receiverSocketId = receiver.socketId;
        const receiverUsername = receiver.username;

        // Emit message to receiver
        io.to(receiverSocketId).emit('private message', {
          senderId,
          senderUsername,
          receiverId,
          receiverUsername,
          message,
          timestamp: new Date()
        });

        // Save to DB
        const newMessage = new Message({
          senderId,
          senderUsername,
          receiverId,
          receiverUsername,
          message
        });
        await newMessage.save();
      } else {
        // Save message even if receiver is offline
        const receiverUser = await User.findById(receiverId);
        if (receiverUser) {
          const receiverUsername = receiverUser.username;
          const newMessage = new Message({
            senderId,
            senderUsername,
            receiverId,
            receiverUsername,
            message
          });
          await newMessage.save();
          socket.emit('message saved', { success: true, message: 'Message saved (receiver offline)' });
        } else {
          socket.emit('error', 'Receiver not found');
        }
      }
    } catch (err) {
      console.error('Message Error:', err);
      socket.emit('error', 'Server error while processing message');
    }
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      delete users[socket.userId];
      console.log(`❌ User disconnected: ${socket.username} (${socket.userId})`);
    }
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
