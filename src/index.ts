// src/index.ts
import dotenv from 'dotenv';
// Load environment variables first
dotenv.config();

import express from 'express';
import clientRoutes from './routes/clientRoutes';
import { Request, Response, NextFunction } from "express";
import { Role } from './types/roles'; // Keep Role import if needed by requireFirebaseRole
import { getCheckInsController } from './controllers/clientController';
import { adminRateLimiter, staffRateLimiter } from './middleware/ratelimiter';
import cors, { CorsOptions } from 'cors';
// Keep redisClient if used for rate limiting or other purposes
import { redisClient } from './config/redis';
// Import the authentication middleware from the dedicated file
import { verifyFirebaseToken, requireFirebaseRole } from './middleware/auth';
// Import DecodedIdToken type for Request augmentation
import { DecodedIdToken } from 'firebase-admin/auth';
import { getUserProfile } from './controllers/userController'; // Import the new controller

// --- Define User type based on Firebase + Roles ---
// Augment Express Request to include the user object populated by middleware
declare global {
  namespace Express {
    interface Request {
      user?: DecodedIdToken & { roles?: Role[], activeRole?: Role };
    }
  }
}
// --- End User Type Definition ---


const app = express();
// Trust the first proxy hop (important if behind a proxy like Vercel)
app.set('trust proxy', 1);

const V_CLIENT_URL = process.env.CLIENT_URL;
console.log("Client_url:", V_CLIENT_URL);

// --- Environment Variable Validation ---
// Keep checks relevant to the current setup
if (!process.env.ADMIN_EMAILS || !process.env.STAFF_EMAILS || !process.env.VOLUNTEER_EMAILS) {
    console.warn("Warning: Role email lists (ADMIN_EMAILS, STAFF_EMAILS, VOLUNTEER_EMAILS) are not fully configured.");
}
// --- End Environment Variable Validation ---


// Approved domains
const allowedOrigins = [
  'http://localhost:5173', // Local development
  'https://client-check-in-app-ui.vercel.app', // Your frontend
  V_CLIENT_URL
].filter((url): url is string => typeof url === 'string' && url.length > 0)
 .map(url => url.toLowerCase());

console.log('Allowed Origins:', allowedOrigins);

// --- Define CORS options ---
const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    const requestOrigin = origin?.toLowerCase();
    console.log('CORS Check - Request Origin:', requestOrigin ?? 'undefined');
    if (!requestOrigin || allowedOrigins.includes(requestOrigin)) {
      console.log('CORS Check - Allowed:', requestOrigin ?? 'undefined');
      callback(null, true);
    } else {
      console.error(`CORS Check - Blocked: ${origin}`);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true, // Keep true if needed for other reasons
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control'], // Ensure Authorization is allowed
};
// --- End Define CORS options ---

// --- Middleware Setup ---

// 1. Handle OPTIONS requests globally first
app.options('*', cors(corsOptions));

// 2. Apply global CORS settings
app.use(cors(corsOptions));

// 3. Request logging
app.use((req, res, next) => {
  const start = Date.now();
  const logPrefix = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl || req.url}`;
  console.log(`\n=== New Request ===\n${logPrefix}`);
  if (req.headers.authorization) {
      console.log('Authorization Header Present: Yes');
  }
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request Body (keys):', Object.keys(req.body));
  }
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${logPrefix} - ${res.statusCode} (${duration}ms)\n=== End Request ===\n`);
  });
  res.header('Vary', 'Origin');
  next();
});

// 4. Body parsing middleware
app.use(express.json());

// 5. Trailing slash redirect middleware
app.use((req, res, next) => {
  if (req.path.endsWith('/') && req.path.length > 1) {
    const query = req.url.slice(req.path.length);
    const newPath = req.path.slice(0, -1);
    console.log(`Redirecting trailing slash: ${req.originalUrl} -> ${newPath}${query}`);
    return res.redirect(301, newPath + query);
  }
  next();
});

// --- End Middleware Setup ---


// --- Route Definitions ---

// Health check route (unprotected)
app.get('/api/health', (req, res) => {
  console.log('[Health Check] Server is running');
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// --- Protected API Routes ---
console.log('getUserProfile imported:', typeof getUserProfile);
console.log('verifyFirebaseToken imported:', typeof verifyFirebaseToken);

app.get('/api/profile', verifyFirebaseToken, getUserProfile);

// Apply imported authentication and authorization middleware

// Example protected route requiring ADMIN role
app.get('/api/dashboard/check-ins',
  adminRateLimiter,
  verifyFirebaseToken, // Use imported middleware
  requireFirebaseRole(Role.ADMIN), // Use imported middleware
  getCheckInsController
);

// Mount other client-related API routes under '/api'
// These require at least VOLUNTEER role
app.use('/api',
  staffRateLimiter,
  verifyFirebaseToken, // Use imported middleware
  requireFirebaseRole(Role.VOLUNTEER), // Use imported middleware
  clientRoutes // Assuming clientRoutes contains handlers for /api/clients, etc.
);

// --- End Protected API Routes ---


// --- Central Error Handling Middleware ---
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[Unhandled Error]', err);
  const responseError = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message || 'Internal server error';
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: responseError });
});
// --- End Central Error Handling Middleware ---


// --- Graceful Shutdown Logic ---
// Keep Redis shutdown if still used (e.g., for rate limiting)
const gracefulShutdown = async (signal: string) => {
  console.log(`Received ${signal}. Closing server and Redis connection...`);
  try {
    if (redisClient && redisClient.isReady) {
      await redisClient.quit();
      console.log('Redis connection closed.');
    } else if (redisClient) {
      console.log('Redis client exists but not connected or already closing.');
    } else {
        console.log('Redis client not configured, skipping shutdown.');
    }
    process.exit(0);
  } catch (err) {
    console.error('Error during graceful shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
// --- End Graceful Shutdown Logic ---


// --- Server Start (for local development) ---
if (process.env.NODE_ENV !== 'production' && process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3001;
  const server = app.listen(PORT, () => {
    console.log(`\n🚀 Server running locally on port ${PORT}`);
    if (redisClient) {
        console.log(`   Redis client connected: ${redisClient.isReady}`);
    }
    console.log(`   Allowed Origins: ${allowedOrigins.join(', ')}`);
    console.log(`   Client URL: ${V_CLIENT_URL}`);
    console.log(`Press CTRL+C to stop\n`);
  });

  // Update local graceful shutdown
  const localGracefulShutdown = async (signal: string) => {
      console.log(`Received ${signal}. Closing local server and Redis connection...`);
      server.close(async () => {
          console.log('HTTP server closed.');
          try {
              if (redisClient && redisClient.isReady) {
                  await redisClient.quit();
                  console.log('Redis connection closed.');
              } else if (redisClient) {
                  console.log('Redis client exists but not connected or already closing.');
              } else {
                  console.log('Redis client not configured, skipping shutdown.');
              }
              process.exit(0);
          } catch (err) {
              console.error('Error closing Redis connection during shutdown:', err);
              process.exit(1);
          }
      });
  };
  process.off('SIGINT', gracefulShutdown);
  process.off('SIGTERM', gracefulShutdown);
  process.on('SIGINT', () => localGracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => localGracefulShutdown('SIGTERM'));
}
// --- End Server Start ---


// --- Vercel Serverless Function Export ---
export default async (req: express.Request, res: express.Response) => {
  // Keep Redis connection check if Redis is still used
  if (redisClient && !redisClient.isReady) {
    try {
      console.warn('Redis client not ready on Vercel invocation. Attempting to connect...');
      await redisClient.connect();
      console.log('Redis reconnected successfully.');
    } catch (err) {
      console.error('Error reconnecting Redis on Vercel function invocation:', err);
      console.warn('Proceeding without guaranteed Redis connection.');
      // Consider if you need to return an error if Redis is critical
      // return res.status(503).json({ error: "Service temporarily unavailable." });
    }
  }
  // Process the request using the configured Express app
  await app(req, res);
};
// --- End Vercel Serverless Function Export ---

