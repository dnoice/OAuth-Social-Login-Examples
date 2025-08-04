# OAuth Authentication System - Project Structure

## 📁 Directory Structure

```
oauth-auth-system/
├── client/                      # Frontend application
│   ├── public/
│   │   ├── index.html          # Main HTML file
│   │   ├── login.html          # Login page
│   │   └── dashboard.html      # Protected dashboard
│   ├── css/
│   │   ├── main.css           # Main styles
│   │   ├── components.css     # Component styles
│   │   └── animations.css     # Animation styles
│   ├── js/
│   │   ├── auth.js           # Authentication logic
│   │   ├── api.js            # API communication
│   │   ├── utils.js          # Utility functions
│   │   └── dashboard.js      # Dashboard functionality
│   └── assets/
│       └── icons/             # SVG icons
│
├── server/                     # Backend application
│   ├── src/
│   │   ├── controllers/
│   │   │   ├── authController.js    # Authentication handlers
│   │   │   └── userController.js    # User management
│   │   ├── middleware/
│   │   │   ├── auth.js             # Authentication middleware
│   │   │   ├── rateLimiter.js      # Rate limiting
│   │   │   ├── validation.js       # Input validation
│   │   │   └── errorHandler.js     # Error handling
│   │   ├── models/
│   │   │   ├── User.js            # User model
│   │   │   └── Session.js         # Session model
│   │   ├── routes/
│   │   │   ├── auth.js            # Auth routes
│   │   │   └── user.js            # User routes
│   │   ├── services/
│   │   │   ├── googleAuth.js      # Google OAuth service
│   │   │   ├── microsoftAuth.js   # Microsoft OAuth service
│   │   │   ├── githubAuth.js      # GitHub OAuth service
│   │   │   └── tokenService.js    # JWT token management
│   │   ├── utils/
│   │   │   ├── database.js        # Database connection
│   │   │   ├── logger.js          # Logging utility
│   │   │   └── crypto.js          # Encryption utilities
│   │   └── app.js                 # Express app setup
│   └── index.js                   # Server entry point
│
├── config/
│   ├── default.json              # Default configuration
│   ├── production.json           # Production config
│   └── development.json          # Development config
│
├── .env.example                  # Environment variables template
├── .gitignore                    # Git ignore file
├── package.json                  # Node.js dependencies
├── docker-compose.yml            # Docker configuration
└── README.md                     # This file
```

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ 
- PostgreSQL or MongoDB
- Redis (for session storage)
- OAuth App credentials from Google, Microsoft, and GitHub

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/oauth-auth-system.git
cd oauth-auth-system
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your credentials
```

4. **Run database migrations**
```bash
npm run migrate
```

5. **Start the development server**
```bash
npm run dev
```

## 🔐 Security Features

- **JWT-based authentication** with refresh tokens
- **Rate limiting** on all endpoints
- **CSRF protection** with double-submit cookies
- **Input validation** and sanitization
- **SQL injection prevention** with parameterized queries
- **XSS protection** with Content Security Policy
- **HTTPS enforcement** in production
- **Secure session management** with Redis
- **Password hashing** with bcrypt
- **Account lockout** after failed attempts

## 📝 API Endpoints

### Authentication
- `POST /api/auth/login` - Email/password login
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/google` - Google OAuth redirect
- `GET /api/auth/google/callback` - Google OAuth callback
- `GET /api/auth/microsoft` - Microsoft OAuth redirect
- `GET /api/auth/microsoft/callback` - Microsoft OAuth callback
- `GET /api/auth/github` - GitHub OAuth redirect
- `GET /api/auth/github/callback` - GitHub OAuth callback

### User Management
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update user profile
- `DELETE /api/user/account` - Delete user account
- `POST /api/user/verify-email` - Send verification email
- `GET /api/user/verify/:token` - Verify email token

## 🛠 Technology Stack

### Frontend
- Vanilla JavaScript (ES6+)
- CSS3 with CSS Variables
- Web Components for reusability
- Service Workers for offline capability

### Backend
- Node.js with Express.js
- PostgreSQL/MongoDB for data
- Redis for sessions
- JWT for authentication
- Passport.js for OAuth strategies

### DevOps
- Docker for containerization
- GitHub Actions for CI/CD
- Nginx for reverse proxy
- Let's Encrypt for SSL

## 📊 Database Schema

### Users Table
- `id` (UUID, Primary Key)
- `email` (String, Unique)
- `password` (String, Hashed)
- `name` (String)
- `avatar` (String)
- `provider` (Enum: local, google, microsoft, github)
- `provider_id` (String)
- `email_verified` (Boolean)
- `two_factor_enabled` (Boolean)
- `two_factor_secret` (String)
- `created_at` (Timestamp)
- `updated_at` (Timestamp)

### Sessions Table
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `token` (String, Unique)
- `ip_address` (String)
- `user_agent` (String)
- `expires_at` (Timestamp)
- `created_at` (Timestamp)

## 🔧 Configuration

See `config/default.json` for all available configuration options.

## 📄 License

MIT License - See LICENSE file for details
