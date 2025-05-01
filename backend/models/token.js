'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Token extends Model {
    static associate(models) {
    }
  }
  Token.init({
    userId: DataTypes.INTEGER,
    token: DataTypes.STRING,
    type: DataTypes.STRING,
    expires: DataTypes.DATE
  }, {
    sequelize,
    modelName: 'Token',
  });
  return Token;
};
