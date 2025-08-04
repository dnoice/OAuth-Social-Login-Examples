/**
 * Database Connection Utility
 * Handles connections to PostgreSQL and MongoDB
 */

const mongoose = require('mongoose');
const { Sequelize } = require('sequelize');
const logger = require('./logger');

// Database type from environment
const DB_TYPE = process.env.DB_TYPE || 'postgresql';

let sequelize;
let mongoConnection;

/**
 * PostgreSQL connection using Sequelize
 */
const connectPostgreSQL = async () => {
  try {
    const dbConfig = {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'oauth_auth_db',
      username: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'password',
      dialect: 'postgres',
      logging: process.env.NODE_ENV === 'development' ? logger.debug.bind(logger) : false,
      pool: {
        max: 10,
        min: 0,
        acquire: 30000,
        idle: 10000
      },
      dialectOptions: {
        ssl: process.env.NODE_ENV === 'production' ? {
          require: true,
          rejectUnauthorized: false
        } : false
      }
    };

    sequelize = new Sequelize(
      dbConfig.database,
      dbConfig.username,
      dbConfig.password,
      dbConfig
    );

    // Test connection
    await sequelize.authenticate();
    logger.info('PostgreSQL connection established successfully');

    // Sync models in development
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
      logger.info('PostgreSQL models synchronized');
    }

    return sequelize;
  } catch (error) {
    logger.error('PostgreSQL connection error:', error);
    throw error;
  }
};

/**
 * MongoDB connection using Mongoose
 */
const connectMongoDB = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/oauth_auth_db';
    
    const mongoOptions = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4
    };

    // Set up mongoose connection events
    mongoose.connection.on('connected', () => {
      logger.info('MongoDB connected successfully');
    });

    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    // Connect to MongoDB
    mongoConnection = await mongoose.connect(mongoUri, mongoOptions);
    
    return mongoConnection;
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    throw error;
  }
};

/**
 * Connect to database based on configuration
 */
const connectDatabase = async () => {
  try {
    if (DB_TYPE === 'mongodb') {
      await connectMongoDB();
    } else {
      await connectPostgreSQL();
    }
    
    logger.info(`Successfully connected to ${DB_TYPE} database`);
  } catch (error) {
    logger.error(`Failed to connect to ${DB_TYPE} database:`, error);
    
    // Retry connection after 5 seconds
    logger.info('Retrying database connection in 5 seconds...');
    setTimeout(connectDatabase, 5000);
  }
};

/**
 * Get Sequelize instance
 */
const getSequelize = () => {
  if (!sequelize) {
    throw new Error('PostgreSQL connection not established');
  }
  return sequelize;
};

/**
 * Get Mongoose connection
 */
const getMongoose = () => {
  if (!mongoConnection) {
    throw new Error('MongoDB connection not established');
  }
  return mongoConnection;
};

/**
 * Close database connections
 */
const closeDatabaseConnections = async () => {
  try {
    if (sequelize) {
      await sequelize.close();
      logger.info('PostgreSQL connection closed');
    }
    
    if (mongoConnection) {
      await mongoose.connection.close();
      logger.info('MongoDB connection closed');
    }
  } catch (error) {
    logger.error('Error closing database connections:', error);
  }
};

/**
 * Database health check
 */
const checkDatabaseHealth = async () => {
  try {
    if (DB_TYPE === 'mongodb') {
      const state = mongoose.connection.readyState;
      return {
        type: 'MongoDB',
        connected: state === 1,
        state: ['disconnected', 'connected', 'connecting', 'disconnecting'][state]
      };
    } else {
      await sequelize.authenticate();
      return {
        type: 'PostgreSQL',
        connected: true,
        state: 'connected'
      };
    }
  } catch (error) {
    return {
      type: DB_TYPE,
      connected: false,
      state: 'error',
      error: error.message
    };
  }
};

module.exports = {
  connectDatabase,
  closeDatabaseConnections,
  getSequelize,
  getMongoose,
  checkDatabaseHealth,
  sequelize,
  mongoose
};
