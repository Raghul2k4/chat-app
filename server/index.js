const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

const JWT_SECRET = 'your_jwt_secret_key';

// MongoDB Connect
mongoose.connect('mongodb://127.0.0.1:27017/jwtChatDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: String
});
const User = mongoose.model('User', userSchema);

// Message Schema - Modified to include username fields
const messageSchema = new mongoose.Schema({
  senderId: String,
  senderUsername: String,
  receiverId: String,
  receiverUsername: String,
  message: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// API: Signup
app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  const userExist = await User.findOne({ username });
  if (userExist) return res.status(400).json({ error: 'Username already taken' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();
  res.json({ message: 'User registered successfully' });
});

// API: Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, userId: user._id, username: user.username });
});

// API: Get all users (for user selection in chat)
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({}, { username: 1, _id: 1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: Get chat history with usernames
app.get('/messages/:senderId/:receiverId', async (req, res) => {
  try {
    const { senderId, receiverId } = req.params;
    const messages = await Message.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId }
      ]
    }).sort({ timestamp: 1 });

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: Protected route (example)
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: 'This is a protected route', userId: req.userId, username: req.username });
});

// JWT verification middleware
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

// Socket.IO - One-to-One Chat with usernames
const users = {}; // Map: userId -> {socketId, username}

io.on('connection', (socket) => {
  console.log('New socket connected');

  socket.on('register user', ({ userId, username }) => {
    // Fixed logging to show actual values instead of [object Object]
    users[userId] = { socketId: socket.id, username };
    socket.userId = userId;
    socket.username = username;
    console.log(`User registered: ${username} (${userId})`);
  });

  socket.on('private message', async ({ receiverId, message }) => {
    const senderId = socket.userId;
    const senderUsername = socket.username;
    
    // Get receiver info
    const receiver = users[receiverId];
    
    if (receiver) {
      const receiverSocketId = receiver.socketId;
      const receiverUsername = receiver.username;
      
      // Send message with usernames
      io.to(receiverSocketId).emit('private message', { 
        senderId, 
        senderUsername,
        receiverId,
        receiverUsername, 
        message,
        timestamp: new Date()
      });

      // Save message with usernames
      const newMessage = new Message({ 
        senderId, 
        senderUsername,
        receiverId,
        receiverUsername, 
        message 
      });
      await newMessage.save();
    } else {
      // Get receiver username from database if not online
      try {
        const receiverUser = await User.findById(receiverId);
        if (receiverUser) {
          const receiverUsername = receiverUser.username;
          
          // Save message with usernames even if receiver is offline
          const newMessage = new Message({ 
            senderId, 
            senderUsername,
            receiverId,
            receiverUsername, 
            message 
          });
          await newMessage.save();
          
          socket.emit('message saved', { success: true, message: 'Message saved but user is offline' });
        } else {
          socket.emit('error', 'Receiver not found');
        }
      } catch (err) {
        socket.emit('error', 'Error processing message');
        console.error('Message error:', err);
      }
    }
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      delete users[socket.userId];
      console.log(`User disconnected: ${socket.username} (${socket.userId})`);
    }
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});