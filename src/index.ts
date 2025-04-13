import dotenv from 'dotenv';
// Load environment variables first
dotenv.config();

import express from 'express';
import clientRoutes from './routes/clientRoutes';
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Request, Response, NextFunction } from "express";
import { Role } from './types/roles';
import { requireRole } from './middleware/rbac';

import {getCheckInsController} from './controllers/clientController';
import { adminRateLimiter, staffRateLimiter } from './middleware/ratelimiter'; 
import cors, { CorsOptions } from 'cors';
import { redisStore, redisClient } from './config/redis'; // <-- Import from new file


declare global {
  namespace Express {
    interface User {
      id: string;
      name: string;
      email: string;
      roles: Role[]; 
      activeRole?: Role;      
    }
  }
}

declare module 'express-session' {
  interface SessionData { // changed from Session to SessionData
      loggedIn?: boolean;  // mark these as optional, otherwise you'll have to define them everywhere
      user?: Express.User; //  Use the Express.User interface
  }
}

const app = express();
const V_CLIENT_URL = process.env.CLIENT_URL;
console.log("Client_url", process.env.CLIENT_URL);

// Approved domains (add more as needed)
const allowedOrigins = [
  'http://localhost:5173', // Local development
  'https://client-check-in-app-ui.vercel.app', // Your frontend
  ...(process.env.CLIENT_URL ? [process.env.CLIENT_URL] : []) // Fallback
].filter(Boolean).map(url => url.toLowerCase());;


// --- Define CORS options ---
const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    const requestOrigin = origin?.toLowerCase(); // Handle potential undefined origin
    console.log('CORS Check - Request Origin:', requestOrigin);
    console.log('CORS Check - Allowed Origins:', allowedOrigins);
    // Allow requests with no origin OR if origin is in the allowed list
    if (!requestOrigin || allowedOrigins.includes(requestOrigin)) {
      console.log('CORS Check - Allowed:', requestOrigin);
      callback(null, true);
    } else {
      console.error(`CORS Check - Blocked: ${origin}`); // Log blocked origins clearly
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Ensure OPTIONS is included
  allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control'], // Ensure Cache-Control is here
};
// --- End Define CORS options ---

// --- Explicitly handle OPTIONS requests first ---
// This ensures preflight requests are handled correctly before other middleware/routes.
app.options('*', cors(corsOptions));
// --- End Explicit OPTIONS handler ---

// --- Apply CORS to all subsequent requests ---
app.use(cors(corsOptions));
// --- End Apply CORS ---


// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  console.log('\n=== New Request ===');
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
  }
  if (Object.keys(req.query).length > 0) {
    console.log('Query Parameters:', JSON.stringify(req.query, null, 2));
  }
  if (Object.keys(req.params).length > 0) {
    console.log('Route Parameters:', JSON.stringify(req.params, null, 2));
  }
  
  // Log response
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - ${res.statusCode} (${duration}ms)`);
    console.log('=== End Request ===\n');
  });
  res.header('Vary', 'Origin'); // Important for cache control

  next();
});

// Middleware
app.use(express.json());

// Health check route
app.get('/api/health', (req, res) => {
  console.log('[Health Check] Server is running');
  res.json({ status: 'ok' });
});


// Session configuration
app.use(
  session({
    store: redisStore, // <-- Use the imported store
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
    },
  })
);
app.use((req, res, next) => {
  console.log("=== Session Middleware ===");
  console.log("req.sessionID:", req.sessionID); // Log the session ID
  console.log("req.path", req.path);
  next();
});
// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

const getRoles = (email: string): Role[] => {
  const adminEmails = process.env.ADMIN_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
  const staffEmails = process.env.STAFF_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
  const volunteerEmails = process.env.VOLUNTEER_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];

  const assignedRoles: Role[] = [];
  const lowerCaseEmail = email.toLowerCase();
  // Check for roles hierarchically and add all applicable ones
  if (adminEmails.includes(lowerCaseEmail)) {
    assignedRoles.push(Role.ADMIN, Role.STAFF, Role.VOLUNTEER);
  } else if (staffEmails.includes(lowerCaseEmail)) {
    assignedRoles.push(Role.STAFF, Role.VOLUNTEER);
  } else if (volunteerEmails.includes(lowerCaseEmail)) {
    assignedRoles.push(Role.VOLUNTEER);
  }


  return assignedRoles;
};

// Google OIDC strategy
passport.use(
  
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
      scope: ["openid", "email", "profile"],
    },
    (accessToken, refreshToken, profile, done) => {
      const email = profile.emails?.[0].value || "";
      const roles = email ? getRoles(email) : [];

      // --- Determine a default active role ---
      let defaultActiveRole: Role | undefined = undefined;
      if (roles.includes(Role.ADMIN)) {
        defaultActiveRole = Role.ADMIN;
      } else if (roles.includes(Role.STAFF)) {
        defaultActiveRole = Role.STAFF;
      } else if (roles.includes(Role.VOLUNTEER)) {
        // Only set Volunteer if it's the only role or highest available
        defaultActiveRole = Role.VOLUNTEER;
      }
      // --- End Determine default active role ---

      const user: Express.User = {
        id: profile.id,
        name: profile.displayName || 'Guest',
        email: email,
        roles: roles,
        activeRole: defaultActiveRole // <-- Assign the determined role here
      };
      done(null, user); // Pass the user object with activeRole to Passport
    }
  )
  
);

// Serialize/deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user: Express.User, done) => done(null, user));
console.log('V_CLIENT_URL:', V_CLIENT_URL);
// Routes
app.get("/auth/google", passport.authenticate("google"));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req: Request, res: Response) => {
    console.log("=== /auth/google/callback ===");
    console.log("req.user:", req.user);
    console.log("Before session:", req.session);
    req.session.user = req.user;
    req.session.loggedIn = true;
    console.log("After session:", req.session);
    res.redirect(`${V_CLIENT_URL}`);
  }
);

app.get("/auth/status", (req: Request, res: Response) => {
  try {
      console.log("auth/status called", req.isAuthenticated(), req.user);
      res.json({ isAuthenticated: req.isAuthenticated(), user: req.user });
  } catch (error) {
      console.error("Error in /auth/status:", error);
      res.status(500).json({ error: "Internal Server Error" }); // Explicitly handle the error
  }
});

// Add this to your Express routes
app.post("/auth/logout", (req: Request, res: Response)  => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Logout failed');
    }
    req.session.destroy(() => {
      res.clearCookie('connect.sid'); // Clear session cookie
      res.sendStatus(200);
    });
  });
});

app.get('/api/dashboard/check-ins',
  adminRateLimiter,
  requireRole(Role.ADMIN), 
  getCheckInsController      
);

// API routes
app.use('/api', 
  staffRateLimiter, 
  requireRole(Role.VOLUNTEER), 
  clientRoutes
);



// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[Error] Unhandled error:', err);
  console.error('Stack trace:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const gracefulShutdown = async (signal: string) => {
  console.log(`Received ${signal}. Closing Redis connection...`);
  try {
    await redisClient.quit(); // <-- Use the imported client
    console.log('Redis connection closed.');
    process.exit(0);
  } catch (err) {
    console.error('Error closing Redis connection:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Redis client connected: ${redisClient.isReady}`);
});


module.exports = (req: express.Request, res: express.Response) => {
  app(req, res);
};
app.get('/api/data', (req, res) => {
  res.json({ message: "Working!" });
});
// Vercel-specific export
export default async (req: express.Request, res: express.Response) => {
  if (!redisClient.isReady) {
    console.warn('Vercel function invoked but Redis not ready.');
  
  }  
  await app(req, res);
};

