const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User, Token } = require('../models');
require('dotenv').config();

router.post('/token', async (req, res) => {

  // 1. Validate Basic Auth
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    console.error('Missing or invalid Authorization header');
    return res.status(401).json({ error: 'Unauthorized - Missing client credentials' });
  }

  try {
    // 2. Extract and verify client credentials
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [clientId, clientSecret] = credentials.split(':');
    
    if (clientId !== 'express-client' || clientSecret !== 'express-secret') {
      console.error('Invalid client credentials');
      return res.status(401).json({ error: 'Unauthorized - Invalid client credentials' });
    }

    // 3. Validate request body
    if (!req.body.grant_type) {
      console.error('Missing grant_type');
      return res.status(400).json({ error: 'Missing grant_type' });
    }

    // 4. Handle different grant types
    if (req.body.grant_type === 'password') {
      console.log('Processing password grant flow');
      
      // 4.1 Validate credentials
      if (!req.body.username || !req.body.password) {
        console.error('Missing username or password');
        return res.status(400).json({ error: 'Missing username or password' });
      }

      // 4.2 Find user
      const user = await User.findOne({ where: { username: req.body.username } });
      if (!user) {
        console.error('User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // 4.3 Verify password
      const validPassword = await bcrypt.compare(req.body.password, user.password);
      if (!validPassword) {
        console.error('Password mismatch');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // 4.4 Generate tokens
      const accessToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { id: user.id, username: user.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
      );

      // 4.5 Store refresh token
      await Token.create({
        userId: user.id,
        token: refreshToken,
        type: 'refresh',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      });

      console.log('Tokens generated successfully');
      
      // 4.6 Return response
      return res.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'Bearer',
        expires_in: 900 // 15 minutes in seconds
      });

    } else if (req.body.grant_type === 'refresh_token') {
      console.log('Processing refresh token flow');
      
      // 5.1 Validate refresh token
      if (!req.body.refresh_token) {
        console.error('Missing refresh_token');
        return res.status(400).json({ error: 'Missing refresh_token' });
      }

      // 5.2 Verify refresh token exists in DB
      const tokenRecord = await Token.findOne({
        where: { 
          token: req.body.refresh_token,
          type: 'refresh'
        }
      });

      if (!tokenRecord) {
        console.error('Invalid refresh token');
        return res.status(403).json({ error: 'Invalid refresh token' });
      }

      // 5.3 Verify JWT
      jwt.verify(req.body.refresh_token, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) {
          console.error('Refresh token verification failed:', err);
          return res.sendStatus(403);
        }

        // 5.4 Generate new access token
        const newAccessToken = jwt.sign(
          { id: user.id, username: user.username },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: '15m' }
        );

        console.log('New access token generated via refresh token');
        
        return res.json({
          access_token: newAccessToken,
          token_type: 'Bearer',
          expires_in: 900
        });
      });

    } else {
      console.error('Unsupported grant_type:', req.body.grant_type);
      return res.status(400).json({ error: 'Unsupported grant_type' });
    }

  } catch (err) {
    console.error('Token endpoint error:', err);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

router.post('/signup', async (req, res) => {
  try {
    const { username, password, name } = req.body;
    
    // Validate input
    if (!username || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const newUser = await User.create({ username, password, name });
    res.status(201).json({ message: 'Registration successful', user: newUser });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// OAuth2 Token Endpoint
router.post('/oauth/token', async (req, res) => {
  const { username, password, grant_type, refresh_token } = req.body;
  
  // Basic Auth for client credentials
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [clientId, clientSecret] = credentials.split(':');

  // Verify client credentials (in a real app, store these in DB)
  if (clientId !== 'express-client' || clientSecret !== 'express-secret') {
    return res.status(401).json({ error: 'Invalid client credentials' });
  }

  try {
    if (grant_type === 'password') {
      // Password grant type (login)
      const user = await User.findOne({ where: { username } });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

      // Generate tokens
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      // Save refresh token to DB
      await Token.create({
        userId: user.id,
        token: refreshToken,
        type: 'refresh',
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      });

      return res.json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'Bearer',
        expires_in: 3600 // 1 hour
      });

    } else if (grant_type === 'refresh_token') {
      // Refresh token grant type
      const tokenRecord = await Token.findOne({ 
        where: { token: refresh_token, type: 'refresh' } 
      });
      
      if (!tokenRecord) return res.status(403).json({ error: 'Invalid refresh token' });

      // Verify refresh token
      jwt.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) return res.sendStatus(403);

        // Generate new access token
        const newAccessToken = generateAccessToken(user);

        return res.json({
          access_token: newAccessToken,
          token_type: 'Bearer',
          expires_in: 3600
        });
      });
    } else {
      return res.status(400).json({ error: 'Unsupported grant type' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper functions
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '1h' }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
}

module.exports = router;
