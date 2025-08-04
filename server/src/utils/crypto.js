/**
 * Crypto Utility
 * Encryption, hashing, and security utilities
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const logger = require('./logger');

// Configuration
const ALGORITHM = 'aes-256-gcm';
const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 64;

/**
 * Hash a password using bcrypt
 */
const hashPassword = async (password) => {
  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    logger.error('Error hashing password:', error);
    throw new Error('Failed to hash password');
  }
};

/**
 * Compare password with hash
 */
const comparePassword = async (password, hash) => {
  try {
    const isMatch = await bcrypt.compare(password, hash);
    return isMatch;
  } catch (error) {
    logger.error('Error comparing password:', error);
    throw new Error('Failed to compare password');
  }
};

/**
 * Encrypt data using AES-256-GCM
 */
const encrypt = (text) => {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  } catch (error) {
    logger.error('Error encrypting data:', error);
    throw new Error('Failed to encrypt data');
  }
};

/**
 * Decrypt data using AES-256-GCM
 */
const decrypt = (encryptedData) => {
  try {
    const { encrypted, iv, authTag } = encryptedData;
    
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      Buffer.from(ENCRYPTION_KEY),
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    logger.error('Error decrypting data:', error);
    throw new Error('Failed to decrypt data');
  }
};

/**
 * Generate random token
 */
const generateToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate secure random string
 */
const generateSecureRandom = (length = 16) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let result = '';
  const randomBytes = crypto.randomBytes(length);
  
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }
  
  return result;
};

/**
 * Hash data using SHA-256
 */
const hashSHA256 = (data) => {
  return crypto
    .createHash('sha256')
    .update(data)
    .digest('hex');
};

/**
 * Generate HMAC
 */
const generateHMAC = (data, secret = process.env.HMAC_SECRET) => {
  return crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('hex');
};

/**
 * Verify HMAC
 */
const verifyHMAC = (data, hmac, secret = process.env.HMAC_SECRET) => {
  const expectedHmac = generateHMAC(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(hmac),
    Buffer.from(expectedHmac)
  );
};

/**
 * Generate 2FA secret
 */
const generate2FASecret = (email, appName = process.env.TWO_FACTOR_APP_NAME || 'OAuth App') => {
  const secret = speakeasy.generateSecret({
    name: `${appName} (${email})`,
    length: 32
  });
  
  return {
    secret: secret.base32,
    qrCode: secret.otpauth_url
  };
};

/**
 * Generate QR code for 2FA
 */
const generateQRCode = async (otpauthUrl) => {
  try {
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);
    return qrCodeDataUrl;
  } catch (error) {
    logger.error('Error generating QR code:', error);
    throw new Error('Failed to generate QR code');
  }
};

/**
 * Verify 2FA token
 */
const verify2FAToken = (token, secret) => {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2 // Allow 2 time steps in either direction
  });
};

/**
 * Generate temporary 2FA token (for testing)
 */
const generate2FAToken = (secret) => {
  return speakeasy.totp({
    secret,
    encoding: 'base32'
  });
};

/**
 * Generate password reset token
 */
const generatePasswordResetToken = () => {
  const token = generateToken(32);
  const expires = new Date(Date.now() + 3600000); // 1 hour
  const hash = hashSHA256(token);
  
  return {
    token,
    hash,
    expires
  };
};

/**
 * Generate email verification token
 */
const generateEmailVerificationToken = () => {
  const token = generateToken(32);
  const expires = new Date(Date.now() + 86400000); // 24 hours
  const hash = hashSHA256(token);
  
  return {
    token,
    hash,
    expires
  };
};

/**
 * Encrypt sensitive fields in an object
 */
const encryptObject = (obj, fieldsToEncrypt) => {
  const encryptedObj = { ...obj };
  
  fieldsToEncrypt.forEach(field => {
    if (obj[field]) {
      const encrypted = encrypt(obj[field].toString());
      encryptedObj[field] = JSON.stringify(encrypted);
    }
  });
  
  return encryptedObj;
};

/**
 * Decrypt sensitive fields in an object
 */
const decryptObject = (obj, fieldsToDecrypt) => {
  const decryptedObj = { ...obj };
  
  fieldsToDecrypt.forEach(field => {
    if (obj[field]) {
      try {
        const encryptedData = JSON.parse(obj[field]);
        decryptedObj[field] = decrypt(encryptedData);
      } catch (error) {
        logger.error(`Error decrypting field ${field}:`, error);
        decryptedObj[field] = obj[field]; // Return original if decryption fails
      }
    }
  });
  
  return decryptedObj;
};

/**
 * Sanitize sensitive data for logging
 */
const sanitizeForLogging = (data) => {
  const sensitiveFields = [
    'password',
    'token',
    'secret',
    'apiKey',
    'creditCard',
    'ssn',
    'pin'
  ];
  
  const sanitized = { ...data };
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '***REDACTED***';
    }
  });
  
  return sanitized;
};

module.exports = {
  hashPassword,
  comparePassword,
  encrypt,
  decrypt,
  generateToken,
  generateSecureRandom,
  hashSHA256,
  generateHMAC,
  verifyHMAC,
  generate2FASecret,
  generateQRCode,
  verify2FAToken,
  generate2FAToken,
  generatePasswordResetToken,
  generateEmailVerificationToken,
  encryptObject,
  decryptObject,
  sanitizeForLogging
};
