# 🌤️ CloudIdada - Complete File Management API Platform

CloudIdada is a powerful, enterprise-grade file management API platform that provides secure file upload, storage, and management capabilities with real-time analytics and multi-API key support.

## 🚀 Quick Start

1. **Clone & Install**
   ```bash
   git clone <repository-url>
   cd cloudidada-main
   npm install
   ```

2. **Environment Setup**
   ```bash
   cp .env.example .env
   # Configure your Firebase and Cloudinary credentials
   ```

3. **Start Server**
   ```bash
   node production-server-direct.js
   ```

4. **Access Dashboard**
   - Console: http://localhost:3000/console.html
   - Health Check: http://localhost:3000/api/health

## 📚 Documentation

- 📖 **[Complete API Guide](./docs/CloudIdada_API_Guide.pdf)** - Comprehensive documentation with examples
- 🎯 **[Quick Start Guide](./docs/Quick_Start.md)** - Get up and running in 5 minutes
- 🔧 **[API Reference](./docs/API_Reference.md)** - Complete API endpoints documentation

## ✨ Features

- 🔐 **Multi-API Key Management** - Generate and manage multiple API keys
- 📁 **File Upload & Storage** - Support for images, documents, videos
- 🔍 **File Preview** - In-browser preview for images and text files  
- 📊 **Real-time Analytics** - Track usage, storage, and performance
- 🌐 **RESTful API** - Clean, consistent API design
- 🔒 **Secure Authentication** - JWT-based user authentication
- ☁️ **Cloud Storage** - Integrated Cloudinary support
- 🎛️ **Web Dashboard** - Beautiful management interface

## 🔑 API Key Usage

### Generate API Key
1. Register/Login at `http://localhost:3000/console.html`
2. Navigate to Dashboard
3. Click "Generate New API Key"
4. Copy your API key (e.g., `cld_demo_8ak2pu`)

### Upload File Example
```bash
curl -X POST http://localhost:3000/api/files/upload \
  -H "x-api-key: YOUR_API_KEY" \
  -F "file=@your-file.jpg"
```

### List Files Example
```bash
curl -X GET http://localhost:3000/api/files/list \
  -H "x-api-key: YOUR_API_KEY"
```

## 🏗️ Architecture

```
CloudIdada Platform
├── Authentication Layer (JWT)
├── API Key Management
├── File Processing Engine
├── Storage Layer (Cloudinary + Local)
├── Analytics Engine
└── Web Dashboard
```

## 📦 File Support

**Images**: JPG, PNG, GIF, WebP, SVG
**Documents**: PDF, TXT, CSV, JSON, HTML, CSS
**Videos**: MP4, WebM
**Max Size**: 10MB per file

## 🔧 Environment Variables

```bash
# Server Configuration
PORT=3000
NODE_ENV=development

# Firebase Configuration
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY=your-private-key
FIREBASE_CLIENT_EMAIL=your-client-email

# Cloudinary Configuration  
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# File Configuration
MAX_FILE_SIZE=10485760
ALLOWED_FILE_TYPES=image/jpeg,image/png,image/gif,image/webp,image/svg+xml,video/mp4,video/webm,application/pdf,text/plain,text/csv,application/json,application/javascript,text/html,text/css
```

## 📈 API Endpoints

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/api/health` | GET | Health check |
| `/api/auth/register` | POST | User registration |
| `/api/auth/login` | POST | User login |
| `/api/files/upload` | POST | Upload file |
| `/api/files/list` | GET | List user files |
| `/api/files/:id/content` | GET | Get file content |
| `/api/user/api-keys` | GET | Get user API keys |
| `/api/user/api-keys/generate` | POST | Generate new API key |

## 🛠️ Development

### Project Structure
```
cloudidada-main/
├── production-server-direct.js    # Main server
├── public/console.html            # Web dashboard
├── uploads/                       # Local file storage
├── package.json                   # Dependencies
└── .env                          # Configuration
```

### Testing
```bash
# Run image upload test
powershell .\image-upload-test.ps1

# Test API endpoints
curl http://localhost:3000/api/health
```

## 🚀 Deployment

### Vercel Deployment
```bash
npm install -g vercel
vercel --prod
```

### Manual Deployment
1. Set environment variables
2. Run `npm install --production`
3. Start with `node production-server-direct.js`

## 🔒 Security Features

- JWT token-based authentication
- API key validation
- File type restrictions
- Size limitations
- CORS protection
- Input sanitization

## 📊 Analytics & Monitoring

- Request tracking per API key
- File upload statistics  
- Storage usage monitoring
- Performance metrics
- Error logging

## 🆘 Support

- 📧 Email: support@cloudidada.com
- 📖 Documentation: [Complete API Guide](./docs/)
- 🐛 Issues: GitHub Issues
- 💬 Community: Discord Server

## 📄 License

MIT License - see LICENSE file for details.

---

**CloudIdada** - Making file management simple and powerful! 🚀