const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const validator = require('validator');
const db = require('../models/db');

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_change_in_production';
const client = new OAuth2Client(CLIENT_ID);

// Validate email format
function isValidEmail(email) {
  return validator.isEmail(email);
}

// Hash password
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Compare password
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Generate JWT token
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '2d' }
  );
}

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Validate email format
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    // Check password length
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if email already exists
    const existingUser = await db.getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await hashPassword(password);
    
    // Add user
    const user = await db.addUser({ 
      name, 
      email, 
      password: hashedPassword 
    });
    
    // Generate token
    const token = generateToken(user);
    
    res.json({ 
      token,
      user: {
        id: user.id, 
        name: user.name, 
        email: user.email
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Validate email format
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    
    // Find user
    const user = await db.getUserByEmail(email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Compare password
    const passwordMatch = await comparePassword(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Generate token
    const token = generateToken(user);
    
    res.json({ 
      token,
      user: {
        id: user.id, 
        name: user.name, 
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Google OAuth login
router.post('/google', async (req, res) => {
  try {
    const { tokenId } = req.body;
    
    if (!tokenId) {
      return res.status(400).json({ error: 'Google token required' });
    }
    
    const ticket = await client.verifyIdToken({
      idToken: tokenId,
      audience: CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const { email, name, picture } = payload;
    
    // Find or create user
    let user = await db.getUserByEmail(email);
    
    if (!user) {
      // Hash a dummy password for Google OAuth users
      const hashedPassword = await hashPassword('google_oauth_' + payload.sub);
      
      user = await db.addUser({ 
        name: name || 'User', 
        email, 
        password: hashedPassword,
        googleId: payload.sub,
        picture
      });
    }
    
    // Generate token
    const token = generateToken(user);
    
    res.json({ 
      token,
      user: {
        id: user.id, 
        name: user.name, 
        email: user.email,
        picture: user.picture
      }
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

// Get user profile with data summary
router.get('/profile/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const user = await db.getUserById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userWorkouts = await db.getWorkoutsByUserId(userId);
    const userNutrition = await db.getNutritionByUserId(userId);
    const userMood = await db.getMoodByUserId(userId);
    
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
      dataStatus: {
        workouts: userWorkouts.length,
        nutritionEntries: userNutrition.length,
        moodEntries: userMood.length,
        totalDataPoints: userWorkouts.length + userNutrition.length + userMood.length,
        message: userWorkouts.length + userNutrition.length + userMood.length === 0 ? 
          'New user - data starts from zero. Start tracking to see your progress!' : 
          'User has tracking data'
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

module.exports = router;

