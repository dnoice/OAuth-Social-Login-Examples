/**
 * Logger Utility
 * Centralized logging configuration using Winston
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  verbose: 4,
  debug: 5,
  silly: 6
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  verbose: 'cyan',
  debug: 'blue',
  silly: 'gray'
};

// Tell winston about the colors
winston.addColors(colors);

// Define format for logs
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Console format with colors
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(metadata).length > 0) {
      msg += ` ${JSON.stringify(metadata)}`;
    }
    return msg;
  })
);

// Define transports
const transports = [];

// Console transport
if (process.env.NODE_ENV !== 'test') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
      level: process.env.LOG_LEVEL || 'debug'
    })
  );
}

// File transport for errors
transports.push(
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: logFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5
  })
);

// File transport for all logs
transports.push(
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    format: logFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  transports,
  exitOnError: false
});

// Create a stream object for Morgan HTTP logging
logger.stream = {
  write: (message) => {
    logger.http(message.trim());
  }
};

// Helper functions for specific log types
logger.logRequest = (req, message, metadata = {}) => {
  const logData = {
    message,
    method: req.method,
    url: req.url,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent'),
    userId: req.user?.id,
    ...metadata
  };
  logger.info(logData);
};

logger.logError = (error, req = null, metadata = {}) => {
  const errorData = {
    message: error.message,
    stack: error.stack,
    code: error.code,
    status: error.status,
    ...metadata
  };

  if (req) {
    errorData.request = {
      method: req.method,
      url: req.url,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
      userId: req.user?.id
    };
  }

  logger.error(errorData);
};

logger.logSecurity = (event, req, metadata = {}) => {
  const securityData = {
    event,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent'),
    userId: req.user?.id,
    timestamp: new Date().toISOString(),
    ...metadata
  };
  
  logger.warn('SECURITY EVENT:', securityData);
  
  // Also write to a separate security log
  const securityLogger = winston.createLogger({
    transports: [
      new winston.transports.File({
        filename: path.join(logsDir, 'security.log'),
        format: logFormat,
        maxsize: 5242880,
        maxFiles: 5
      })
    ]
  });
  
  securityLogger.warn(securityData);
};

logger.logPerformance = (operation, duration, metadata = {}) => {
  const performanceData = {
    operation,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
    ...metadata
  };
  
  logger.verbose('PERFORMANCE:', performanceData);
  
  // Write to performance log if duration exceeds threshold
  if (duration > 1000) { // 1 second
    const performanceLogger = winston.createLogger({
      transports: [
        new winston.transports.File({
          filename: path.join(logsDir, 'performance.log'),
          format: logFormat,
          maxsize: 5242880,
          maxFiles: 5
        })
      ]
    });
    
    performanceLogger.warn('SLOW OPERATION:', performanceData);
  }
};

logger.logAudit = (action, userId, metadata = {}) => {
  const auditData = {
    action,
    userId,
    timestamp: new Date().toISOString(),
    ...metadata
  };
  
  // Write to audit log
  const auditLogger = winston.createLogger({
    transports: [
      new winston.transports.File({
        filename: path.join(logsDir, 'audit.log'),
        format: logFormat,
        maxsize: 5242880,
        maxFiles: 10 // Keep more audit logs
      })
    ]
  });
  
  auditLogger.info(auditData);
  logger.info('AUDIT:', auditData);
};

// Log unhandled errors
if (process.env.NODE_ENV !== 'test') {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', { reason, promise });
  });

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
  });
}

module.exports = logger;
