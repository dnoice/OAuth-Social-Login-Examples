/**
 * Server Entry Point
 * Main file that starts the Express server
 */

require('dotenv').config();
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const app = require('./src/app');
const logger = require('./src/utils/logger');
const { connectDatabase } = require('./src/utils/database');

// Server configuration
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

// Create HTTP server
const httpServer = http.createServer(app);

// Create HTTPS server for production
let httpsServer;
if (isProduction && process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH) {
  try {
    const privateKey = fs.readFileSync(process.env.SSL_KEY_PATH, 'utf8');
    const certificate = fs.readFileSync(process.env.SSL_CERT_PATH, 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    httpsServer = https.createServer(credentials, app);
    logger.info('HTTPS server configured successfully');
  } catch (error) {
    logger.error('Failed to load SSL certificates:', error);
    logger.warn('Falling back to HTTP only');
  }
}

// Graceful shutdown handler
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  
  // Stop accepting new connections
  httpServer.close(() => {
    logger.info('HTTP server closed');
  });
  
  if (httpsServer) {
    httpsServer.close(() => {
      logger.info('HTTPS server closed');
    });
  }
  
  // Close database connections
  const mongoose = require('mongoose');
  if (mongoose.connection.readyState === 1) {
    mongoose.connection.close(() => {
      logger.info('MongoDB connection closed');
    });
  }
  
  // Close Redis connection
  const redis = require('redis');
  const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD
  });
  
  redisClient.quit(() => {
    logger.info('Redis connection closed');
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

// Start the server
const startServer = async () => {
  try {
    // Connect to database
    await connectDatabase();
    logger.info('Database connected successfully');
    
    // Start HTTP server
    httpServer.listen(PORT, () => {
      logger.info(`
        ================================================
        🚀 Server is running in ${NODE_ENV} mode
        🔗 HTTP Server: http://localhost:${PORT}
        📝 API Docs: http://localhost:${PORT}/api-docs
        📊 Health Check: http://localhost:${PORT}/health
        ================================================
      `);
    });
    
    // Start HTTPS server if configured
    if (httpsServer) {
      const httpsPort = process.env.HTTPS_PORT || 443;
      httpsServer.listen(httpsPort, () => {
        logger.info(`🔒 HTTPS Server: https://localhost:${httpsPort}`);
      });
    }
    
    // Log memory usage periodically in development
    if (!isProduction) {
      setInterval(() => {
        const memUsage = process.memoryUsage();
        logger.debug('Memory Usage:', {
          rss: `${Math.round(memUsage.rss / 1024 / 1024)} MB`,
          heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)} MB`,
          heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)} MB`,
          external: `${Math.round(memUsage.external / 1024 / 1024)} MB`
        });
      }, 60000); // Every minute
    }
    
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Initialize server
startServer();

// Export for testing
module.exports = { httpServer, httpsServer };
