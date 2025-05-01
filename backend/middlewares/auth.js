const jwt = require('jsonwebtoken');
const { Token } = require('../models');

module.exports = {
authenticateToken: (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.sendStatus(401);
  
  const token = authHeader.split(' ')[1];
  if (!token || token === 'null') {
    console.error('Invalid token format');
    return res.sendStatus(403);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}};
