import dotenv from 'dotenv';
// Load environment variables first
dotenv.config();

import express from 'express';
import cors from 'cors';
import clientRoutes from './routes/clientRoutes';
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Request, Response, NextFunction } from "express";

declare global {
  namespace Express {
    interface User {
      id: string;
      name: string;
      email: string;
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

app.use(cors({
  origin: (origin, callback) => {
    console.log('Origin:', origin); // Log the origin.toLowerCase
    // Allow requests with no origin (mobile apps, curl, etc)
    if (!origin || allowedOrigins.includes(origin.toLowerCase())) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed`));
    }
    
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Explicitly handle preflight requests
// app.options('*', (req, res) => {
//   res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
//   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
//   res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
//   res.setHeader('Access-Control-Allow-Credentials', 'true');
//   res.status(204).end();
// });
// app.options('*', cors({
//   origin: (origin, callback) => {
//     if (!origin || allowedOrigins.some(o => origin.toLowerCase() === o.toLowerCase())) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   credentials: true
// }));
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

// API routes
app.use('/api', clientRoutes);

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[Error] Unhandled error:', err);
  console.error('Stack trace:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Session configuration
app.use(
  session({
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
// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

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
      const user: Express.User = {
        id: profile.id,
        name: profile.displayName || 'Guest',
        email: profile.emails?.[0].value || "",
      };
      done(null, user);
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
// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
module.exports = (req: express.Request, res: express.Response) => {
  app(req, res);
};
app.get('/api/data', (req, res) => {
  res.json({ message: "Working!" });
});
// Vercel-specific export
export default async (req: express.Request, res: express.Response) => {
  await app(req, res);
};

