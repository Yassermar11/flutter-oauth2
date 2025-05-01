require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { sequelize } = require('./models');
const protectedRoutes = require('./routes/protected');
const app = express();

// Middleware
app.use('/', protectedRoutes);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
const authRoutes = require('./routes/auth');
app.use('/oauth', authRoutes);

// Test route
app.get('/', (req, res) => {
  res.send('OAuth2 Server Running');
});

// Simple route debugging
app.on('mount', () => {
  console.log('\nAvailable routes:');
  console.log('POST /oauth/token');
  console.log('POST /oauth/signup');
  console.log('GET  /');
});

// Database sync and server start
const PORT = process.env.PORT || 3000;
sequelize.sync().then(() => {
  app.listen(PORT, () => {
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});
