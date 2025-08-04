/**
 * Express Application Setup
 * Main application configuration and middleware setup
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const RedisStore = require('connect-redis').default;
const redis = require('redis');
const morgan = require('morgan');
const path = require('path');
const csurf = require('csurf');

// Import middlewar
const rateLimiter = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');
const logger = require('./utils/logger');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

// Import Passport configuration
require('./services/googleAuth');
require('./services/microsoftAuth');
require('./services/githubAuth');

// Create Express app
const app = express();

// Trust proxy - important for production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3001'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  exposedHeaders: ['X-CSRF-Token'],
  maxAge: 86400 // 24 hours
};
app.use(cors(corsOptions));

// Compression middleware
app.use(compression());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'cookie-secret'));

// Logging middleware
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined', { stream: logger.stream }));
} else {
  app.use(morgan('dev'));
}

// Redis client setup for sessions
const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  },
  password: process.env.REDIS_PASSWORD || undefined,
  legacyMode: false
});

redisClient.connect().catch(console.error);

redisClient.on('error', (err) => {
  logger.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  logger.info('Redis Client Connected');
});

// Session configuration
const sessionConfig = {
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  name: process.env.SESSION_NAME || 'sessionId',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
  }
};

app.use(session(sessionConfig));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// CSRF protection (exclude auth routes)
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF selectively
app.use((req, res, next) => {
  // Skip CSRF for OAuth callbacks and API endpoints that use JWT
  if (req.path.includes('/callback') || req.path.includes('/api/auth/refresh')) {
    return next();
  }
  csrfProtection(req, res, next);
});

// Serve static files
app.use('/static', express.static(path.join(__dirname, '../../client/public')));
app.use('/assets', express.static(path.join(__dirname, '../../client/assets')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    memory: process.memoryUsage(),
    redis: redisClient.isReady ? 'connected' : 'disconnected'
  });
});

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// Serve client application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../../client/public/index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../../client/public/login.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../../client/public/dashboard.html'));
});

// 404 handler
app.use((req, res, next) => {
  const error = new Error('Resource not found');
  error.status = 404;
  next(error);
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Cleanup on app termination
process.on('SIGINT', async () => {
  await redisClient.disconnect();
  process.exit(0);
});

module.exports = app;
