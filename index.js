const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticateJWT = require('./authMiddleware');
require('dotenv').config();

const app = express();
const PORT = 3500;

app.use(bodyParser.json());

// In-memory user database with some initial data
const users = [
  { id: 1, username: 'john_doe', password: bcrypt.hashSync('password123', 10) },
  { id: 2, username: 'jane_smith', password: bcrypt.hashSync('mypassword', 10) }
];

// Signup Route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
    return res.status(400).json({ error: "Username already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, username, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: "User created successfully!" });
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  // Generate a JWT token
  const token = jwt.sign({ id: user.id, username: user.username }, process.env.SECRET_KEY, {
    expiresIn: '1h',
  });

  res.status(200).json({ token });
});

// Get All Users (Protected Route)
app.get('/users', authenticateJWT, (req, res) => {
  const safeUsers = users.map(user => ({
    id: user.id,
    username: user.username,
  }));

  res.status(200).json(safeUsers);
});

// Delete a User by ID (Protected Route)
app.delete('/users/:id', authenticateJWT, (req, res) => {
  const userId = parseInt(req.params.id, 10);

  const userIndex = users.findIndex(user => user.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({ error: `User with ID ${userId} not found.` });
  }

  // Check if the requesting user matches the user being deleted
  if (req.user.id !== userId) {
    return res.status(403).json({ error: "You can only delete your own account." });
  }

  users.splice(userIndex, 1);

  res.status(200).json({ message: `User with ID ${userId} deleted successfully.` });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
