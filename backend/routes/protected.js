const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middlewares/auth');

// Protected secret endpoint
router.get('/secret', authenticateToken, (req, res) => {
  res.json({ 
    message: 'This is a protected secret endpoint',
    user: req.user 
  });
});

module.exports = router;
