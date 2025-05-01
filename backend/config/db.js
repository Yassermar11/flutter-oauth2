require('dotenv').config();

module.exports = {
  development: {
    username: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASS || 'postgres',
    database: process.env.DB_NAME || 'oauth_demo',
    host: process.env.DB_HOST || 'localhost',
    dialect: 'postgres',
  },
};
