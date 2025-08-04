/**
 * User Model
 * Supports both MongoDB (Mongoose) and PostgreSQL (Sequelize)
 */

const { DataTypes } = require('sequelize');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const crypto = require('../utils/crypto');
const logger = require('../utils/logger');

// Determine which database to use
const DB_TYPE = process.env.DB_TYPE || 'postgresql';

/**
 * MongoDB Schema using Mongoose
 */
const mongooseUserSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: uuidv4
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: function() {
      return this.provider === 'local';
    }
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  avatar: {
    type: String,
    default: null
  },
  provider: {
    type: String,
    enum: ['local', 'google', 'microsoft', 'github'],
    default: 'local'
  },
  providerId: {
    type: String,
    default: null
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    default: null
  },
  emailVerificationExpires: {
    type: Date,
    default: null
  },
  passwordResetToken: {
    type: String,
    default: null
  },
  passwordResetExpires: {
    type: Date,
    default: null
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  lastLogin: {
    type: Date,
    default: null
  },
  lastPasswordChange: {
    type: Date,
    default: null
  },
  refreshTokens: [{
    token: String,
    createdAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: Date,
    deviceInfo: String
  }],
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    },
    language: {
      type: String,
      default: 'en'
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      },
      sms: {
        type: Boolean,
        default: false
      }
    }
  },
  metadata: {
    ipAddress: String,
    userAgent: String,
    location: {
      country: String,
      city: String,
      coordinates: {
        lat: Number,
        lng: Number
      }
    }
  },
  roles: [{
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  }],
  permissions: [String],
  isActive: {
    type: Boolean,
    default: true
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.twoFactorSecret;
      delete ret.emailVerificationToken;
      delete ret.passwordResetToken;
      delete ret.refreshTokens;
      return ret;
    }
  }
});

// Indexes for MongoDB
mongooseUserSchema.index({ email: 1, provider: 1 });
mongooseUserSchema.index({ providerId: 1, provider: 1 });
mongooseUserSchema.index({ emailVerificationToken: 1 });
mongooseUserSchema.index({ passwordResetToken: 1 });
mongooseUserSchema.index({ createdAt: -1 });

// Virtual for account lock status
mongooseUserSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware for MongoDB
mongooseUserSchema.pre('save', async function(next) {
  try {
    // Hash password if modified
    if (this.isModified('password') && this.password) {
      this.password = await crypto.hashPassword(this.password);
      this.lastPasswordChange = new Date();
    }
    
    // Encrypt 2FA secret if modified
    if (this.isModified('twoFactorSecret') && this.twoFactorSecret) {
      const encrypted = crypto.encrypt(this.twoFactorSecret);
      this.twoFactorSecret = JSON.stringify(encrypted);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods for MongoDB
mongooseUserSchema.methods = {
  comparePassword: async function(candidatePassword) {
    return await crypto.comparePassword(candidatePassword, this.password);
  },
  
  get2FASecret: function() {
    if (!this.twoFactorSecret) return null;
    try {
      const encrypted = JSON.parse(this.twoFactorSecret);
      return crypto.decrypt(encrypted);
    } catch (error) {
      logger.error('Error decrypting 2FA secret:', error);
      return null;
    }
  },
  
  incrementLoginAttempts: async function() {
    // Reset attempts if lock has expired
    if (this.lockUntil && this.lockUntil < Date.now()) {
      return await this.updateOne({
        $set: { loginAttempts: 1 },
        $unset: { lockUntil: 1 }
      });
    }
    
    const updates = { $inc: { loginAttempts: 1 } };
    const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
    const lockTime = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 30;
    
    // Lock account if max attempts reached
    if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
      updates.$set = { lockUntil: new Date(Date.now() + lockTime * 60 * 1000) };
    }
    
    return await this.updateOne(updates);
  },
  
  resetLoginAttempts: async function() {
    return await this.updateOne({
      $set: { loginAttempts: 0, lastLogin: new Date() },
      $unset: { lockUntil: 1 }
    });
  },
  
  generatePasswordResetToken: async function() {
    const { token, hash, expires } = crypto.generatePasswordResetToken();
    this.passwordResetToken = hash;
    this.passwordResetExpires = expires;
    await this.save();
    return token;
  },
  
  generateEmailVerificationToken: async function() {
    const { token, hash, expires } = crypto.generateEmailVerificationToken();
    this.emailVerificationToken = hash;
    this.emailVerificationExpires = expires;
    await this.save();
    return token;
  },
  
  addRefreshToken: async function(token, deviceInfo) {
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    this.refreshTokens.push({
      token: crypto.hashSHA256(token),
      expiresAt,
      deviceInfo
    });
    
    // Keep only last 5 refresh tokens
    if (this.refreshTokens.length > 5) {
      this.refreshTokens = this.refreshTokens.slice(-5);
    }
    
    await this.save();
  },
  
  removeRefreshToken: async function(token) {
    const hashedToken = crypto.hashSHA256(token);
    this.refreshTokens = this.refreshTokens.filter(rt => rt.token !== hashedToken);
    await this.save();
  },
  
  removeExpiredRefreshTokens: async function() {
    this.refreshTokens = this.refreshTokens.filter(rt => rt.expiresAt > new Date());
    await this.save();
  }
};

/**
 * PostgreSQL Model using Sequelize
 */
const createSequelizeModel = (sequelize) => {
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true
      }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: true
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false
    },
    avatar: {
      type: DataTypes.STRING,
      allowNull: true
    },
    provider: {
      type: DataTypes.ENUM('local', 'google', 'microsoft', 'github'),
      defaultValue: 'local'
    },
    providerId: {
      type: DataTypes.STRING,
      allowNull: true
    },
    emailVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    emailVerificationToken: {
      type: DataTypes.STRING,
      allowNull: true
    },
    emailVerificationExpires: {
      type: DataTypes.DATE,
      allowNull: true
    },
    passwordResetToken: {
      type: DataTypes.STRING,
      allowNull: true
    },
    passwordResetExpires: {
      type: DataTypes.DATE,
      allowNull: true
    },
    twoFactorEnabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    twoFactorSecret: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    loginAttempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0
    },
    lockUntil: {
      type: DataTypes.DATE,
      allowNull: true
    },
    lastLogin: {
      type: DataTypes.DATE,
      allowNull: true
    },
    lastPasswordChange: {
      type: DataTypes.DATE,
      allowNull: true
    },
    preferences: {
      type: DataTypes.JSON,
      defaultValue: {
        theme: 'light',
        language: 'en',
        timezone: 'UTC',
        notifications: {
          email: true,
          push: true,
          sms: false
        }
      }
    },
    metadata: {
      type: DataTypes.JSON,
      defaultValue: {}
    },
    roles: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      defaultValue: ['user']
    },
    permissions: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      defaultValue: []
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    },
    isDeleted: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    deletedAt: {
      type: DataTypes.DATE,
      allowNull: true
    }
  }, {
    timestamps: true,
    paranoid: true,
    indexes: [
      { fields: ['email', 'provider'] },
      { fields: ['providerId', 'provider'] },
      { fields: ['emailVerificationToken'] },
      { fields: ['passwordResetToken'] }
    ],
    hooks: {
      beforeCreate: async (user) => {
        if (user.password) {
          user.password = await crypto.hashPassword(user.password);
        }
        if (user.twoFactorSecret) {
          const encrypted = crypto.encrypt(user.twoFactorSecret);
          user.twoFactorSecret = JSON.stringify(encrypted);
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password')) {
          user.password = await crypto.hashPassword(user.password);
          user.lastPasswordChange = new Date();
        }
        if (user.changed('twoFactorSecret') && user.twoFactorSecret) {
          const encrypted = crypto.encrypt(user.twoFactorSecret);
          user.twoFactorSecret = JSON.stringify(encrypted);
        }
      }
    }
  });
  
  // Instance methods for Sequelize
  User.prototype.comparePassword = async function(candidatePassword) {
    return await crypto.comparePassword(candidatePassword, this.password);
  };
  
  User.prototype.get2FASecret = function() {
    if (!this.twoFactorSecret) return null;
    try {
      const encrypted = JSON.parse(this.twoFactorSecret);
      return crypto.decrypt(encrypted);
    } catch (error) {
      logger.error('Error decrypting 2FA secret:', error);
      return null;
    }
  };
  
  return User;
};

// Export appropriate model based on DB_TYPE
let UserModel;

if (DB_TYPE === 'mongodb') {
  UserModel = mongoose.model('User', mongooseUserSchema);
} else {
  // This will be initialized when database connects
  UserModel = null;
}

module.exports = {
  UserModel,
  mongooseUserSchema,
  createSequelizeModel
};
