const dotenv = require('dotenv');
const path = require('path');
const root = path.join.bind(this,__dirname);
dotenv.config({path: root('.env')});

module.exports = {
  PORT: process.env.PORT || 3000,
  MONGO_URL: process.env.MONGO_URL,
  IS_PODUCTION: process.env.NODE_ENV === 'production'
};
