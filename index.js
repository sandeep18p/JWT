const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();  // Load environment variables
const app = express();
const port = 3000;

// Middleware to parse JSON
app.use(express.json());

// In-memory users array (for demonstration purposes)
let users = [];

// JWT Secret (stored in environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Helper function to generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
};

// Route to Register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    // Check if user already exists
    const userExists = users.find(user => user.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save new user (in a real-world app, you'd store this in a database)
    const newUser = { id: Date.now(), username, password: hashedPassword };
    users.push(newUser);

    // Generate JWT token
    const token = generateToken(newUser);

    // Send response
    res.status(201).json({ message: 'User registered successfully', token });
});

// Route to Login a user
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find user
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Compare password with the hashed one
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = generateToken(user);

    // Send response
    res.status(200).json({ message: 'Login successful', token });
});

// Protected route to test authentication
app.get('/protected', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from Authorization header

    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }

        // Token is valid, proceed with the request
        res.status(200).json({ message: 'Protected data accessed', user: decoded });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
