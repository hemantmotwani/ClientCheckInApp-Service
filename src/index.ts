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

import { getCheckInsController } from './controllers/clientController';
import { adminRateLimiter, staffRateLimiter } from './middleware/ratelimiter';
import cors, { CorsOptions } from 'cors';
import { redisStore, redisClient } from './config/redis';
import { OAuth2Client } from 'google-auth-library';


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
  interface SessionData {
    loggedIn?: boolean;
    user?: Express.User;
  }
}

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const app = express();
// Trust the first proxy hop (important for secure cookies if behind a proxy like Vercel)
app.set('trust proxy', 1);

const V_CLIENT_URL = process.env.CLIENT_URL;
console.log("Client_url:", V_CLIENT_URL); // Added colon for clarity

// --- Environment Variable Validation (Optional but Recommended) ---
if (!process.env.SESSION_SECRET) {
    console.error("FATAL ERROR: SESSION_SECRET is not defined.");
    process.exit(1); // Exit if critical env vars are missing
}
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_CALLBACK_URL) {
    console.warn("Warning: Google OAuth environment variables are not fully configured.");
    // Decide if this should be fatal depending on whether the redirect flow is still needed
}
// --- End Environment Variable Validation ---


// Approved domains
const allowedOrigins = [
  'http://localhost:5173', // Local development
  'https://client-check-in-app-ui.vercel.app', // Your frontend
  V_CLIENT_URL // Add CLIENT_URL directly
].filter((url): url is string => typeof url === 'string' && url.length > 0) // Ensure only valid strings remain
 .map(url => url.toLowerCase());

console.log('Allowed Origins:', allowedOrigins); // Log the final list

// --- Define CORS options ---
const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    // Origin can be undefined for same-origin requests or server-to-server
    const requestOrigin = origin?.toLowerCase();
    console.log('CORS Check - Request Origin:', requestOrigin ?? 'undefined');

    // Allow requests with no origin OR if origin is in the allowed list
    if (!requestOrigin || allowedOrigins.includes(requestOrigin)) {
      console.log('CORS Check - Allowed:', requestOrigin ?? 'undefined');
      callback(null, true);
    } else {
      console.error(`CORS Check - Blocked: ${origin}`);
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control'],
};
// --- End Define CORS options ---

// --- Middleware Setup ---

// 1. Handle OPTIONS requests globally first for preflight checks
app.options('*', cors(corsOptions));
									   

// 2. Apply global CORS settings
app.use(cors(corsOptions));
						 


// 3. Request logging
app.use((req, res, next) => {
  const start = Date.now();
									   
  const logPrefix = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl || req.url}`; // Use originalUrl for accuracy behind proxies
  console.log(`\n=== New Request ===\n${logPrefix}`);
  // Consider logging fewer headers in production if needed
  // console.log('Headers:', JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    // Be cautious logging full bodies in production (sensitive data)
    console.log('Request Body (keys):', Object.keys(req.body));
										  
																		 
   
										   
																		  
  }
  // ... other logging ...

  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${logPrefix} - ${res.statusCode} (${duration}ms)\n=== End Request ===\n`);
										 
  });
  res.header('Vary', 'Origin'); // Helps caching proxies differentiate responses

  next();
});

// 4. Body parsing middleware
app.use(express.json());

					 
app.use((req, res, next) => {
  // Use req.path to avoid query string issues
  if (req.path.endsWith('/') && req.path.length > 1) {
    const query = req.url.slice(req.path.length); // Keep query string
    const newPath = req.path.slice(0, -1);
    console.log(`Redirecting trailing slash: ${req.originalUrl} -> ${newPath}${query}`);
    return res.redirect(301, newPath + query);
  }
  next();
});					  
												  
							 
   


// 5. Session configuration
app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET!, // Already checked above
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true, // Prevent client-side JS access
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // Crucial for cross-site/OAuth redirects
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
      // Consider setting domain explicitly if using subdomains and need shared sessions
      // domain: process.env.NODE_ENV === "production" ? '.yourdomain.com' : undefined
    },
  })
);

// Optional: Log session details after setup (useful for debugging)
app.use((req, res, next) => {
  console.log("Session ID:", req.sessionID);
  // console.log("Session Data:", req.session); // Be careful logging full session in production
									
  next();
});

// 6. Passport initialization
app.use(passport.initialize());
app.use(passport.session()); // Connect Passport to the session

// --- End Middleware Setup ---


// --- Helper Functions ---
const getRoles = (email: string): Role[] => {
  const adminEmails = process.env.ADMIN_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
  const staffEmails = process.env.STAFF_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
  const volunteerEmails = process.env.VOLUNTEER_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];

  const assignedRoles: Set<Role> = new Set(); // Use a Set to avoid duplicates easily
  const lowerCaseEmail = email.toLowerCase();

  if (adminEmails.includes(lowerCaseEmail)) {
    assignedRoles.add(Role.ADMIN);
    assignedRoles.add(Role.STAFF);
    assignedRoles.add(Role.VOLUNTEER);
  } else if (staffEmails.includes(lowerCaseEmail)) {
    assignedRoles.add(Role.STAFF);
    assignedRoles.add(Role.VOLUNTEER);
  } else if (volunteerEmails.includes(lowerCaseEmail)) {
    assignedRoles.add(Role.VOLUNTEER);
  }


  return Array.from(assignedRoles); // Convert back to array
};

const determineDefaultActiveRole = (roles: Role[]): Role | undefined => {
  // Prioritize roles
  if (roles.includes(Role.ADMIN)) return Role.ADMIN;
  if (roles.includes(Role.STAFF)) return Role.STAFF;
  if (roles.includes(Role.VOLUNTEER)) return Role.VOLUNTEER;
  return undefined;
};
// --- End Helper Functions ---


// --- Passport Configuration ---
// Google OIDC strategy (for traditional redirect flow)
passport.use(
  
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
      scope: ["openid", "email", "profile"],
    },
    // This verify callback runs when Google redirects back to your callbackURL
    (accessToken, refreshToken, profile, done) => {
      try {
          const email = profile.emails?.[0].value;
          if (!email) {
              // Handle case where email is not provided by Google (should be rare with 'email' scope)
              return done(new Error("Email not found in Google profile"), undefined);
          }
          const roles = getRoles(email);
          const defaultActiveRole = determineDefaultActiveRole(roles);
										  
										  
												 
										  
													 
																		   
											  
		  
												  

          const user: Express.User = {
            id: profile.id, // Google's unique ID
            name: profile.displayName || 'User', // Provide a default name
            email: email,
            roles: roles,
            activeRole: defaultActiveRole
          };
          // Pass the constructed user object to Passport
          // Passport will then call serializeUser
          return done(null, user);
      } catch (error) {
          return done(error as Error, undefined); // Pass any unexpected errors
      }
    }
  )
  
);

// Serialize user: Determine what data to store in the session
// Storing the whole user object is convenient but can increase session size.
// Storing just the ID is more common if you have a user database to re-fetch from.
passport.serializeUser((user, done) => {
  done(null, user); // Store the entire user object in the session
});

// Deserialize user: Retrieve user data from the session on subsequent requests
// This attaches the user object to req.user
passport.deserializeUser((user: Express.User, done) => {
  // If you only stored an ID in serializeUser, you would fetch the full user here.
  // Since we stored the full object, we just pass it along.
  done(null, user);
});
// --- End Passport Configuration ---


// --- Route Definitions ---

// Health check route (unprotected)
app.get('/api/health', (req, res) => {
  console.log('[Health Check] Server is running');
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// --- Authentication Routes ---

// Route to initiate the Google OAuth redirect flow
app.get("/auth/google", passport.authenticate("google")); // Let Passport handle the redirect

// Callback route that Google redirects back to
app.get(
  "/auth/google/callback",
  // Middleware to handle the authentication attempt using the 'google' strategy
  passport.authenticate("google", {
      // Redirect to frontend login page on failure
      failureRedirect: `${V_CLIENT_URL}/login?error=google_auth_failed`,
      failureMessage: true // Optional: Store failure message in session flash
  }),
  // This handler runs ONLY on successful authentication
  (req: Request, res: Response) => {
    console.log("Successful Google OAuth callback. User:", req.user);
    // Session is already established by passport.authenticate calling req.logIn
    // Redirect the user back to the frontend application
    res.redirect(`${V_CLIENT_URL}`); // Redirect to client home/dashboard
  }
);

// Route for Google One Tap token verification (POST request)
app.post("/auth/google/verify-token", async (req: Request, res: Response, next: NextFunction) => {
  console.log("!!!!!! Reached /auth/google/verify-token handler !!!!!!"); // Debug log
  const { token } = req.body;

  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: "ID token (string) is required." });
  }

  try {
    console.log("Verifying Google ID token...");
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID, // Must match the client ID that obtained the token
    });

    const payload = ticket.getPayload();
    console.log("Token verification successful. Payload:", payload);

    if (!payload) {
      // This case should ideally be caught by verifyIdToken throwing an error
      return res.status(401).json({ error: "Invalid ID token payload." });
    }
    if (!payload.email) {
      return res.status(401).json({ error: "Email not found in token payload." });
    }

    // Construct user object from token payload
    const email = payload.email;
    const roles = getRoles(email);
    const defaultActiveRole = determineDefaultActiveRole(roles);

																	
																			
    const user: Express.User = {
      id: payload.sub, // Google's unique user ID
      name: payload.name || 'User',
      email: email,
      roles: roles,
      activeRole: defaultActiveRole
    };
									   

    console.log("User constructed from token:", user);

    // Log the user into the session using Passport's req.logIn
    // This triggers serializeUser and sets up the session cookie
    req.logIn(user, (err) => {
      if (err) {
        console.error("Error during req.logIn after token verification:", err);
        return next(err); // Pass error to the central error handler
      }
      console.log("Session established via req.logIn. Session:", req.session);
											 
      // Send success response - cookie is handled automatically by express-session
      return res.status(200).json({ isAuthenticated: true, user: req.user });
    });
									

  } catch (error) {
    console.error("Error verifying Google ID token:", error);
    // Provide a generic error message but log the specific error
    return res.status(401).json({ error: "Token verification failed." });
  }
});


										   
		 
														 
		
						  
																 
									
												 
									   
												
								
								
											   
									
   
  

// Route to check the current authentication status
app.get("/auth/status", (req: Request, res: Response) => {
  // req.isAuthenticated() is the standard Passport method to check session validity
  const isAuthenticated = req.isAuthenticated();
  console.log("/auth/status - Authenticated:", isAuthenticated, "User:", req.user);
  res.status(200).json({ isAuthenticated: isAuthenticated, user: req.user || null });
													 
																							  
   
});

// Route to handle user logout
app.post("/auth/logout", (req: Request, res: Response, next: NextFunction) => {
  req.logout((err) => { // req.logout is provided by Passport
    if (err) {
      console.error('Logout error:', err);
      return next(err); // Pass error to the central error handler
    }
    // Destroy the session in the store (e.g., Redis)
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Session destruction error:', destroyErr);
        // Still try to clear the cookie and send response, but log the error
        res.clearCookie('connect.sid'); // Clear the session cookie on the client
        return next(destroyErr); // Pass error to the central error handler
      }
      res.clearCookie('connect.sid'); // Ensure cookie is cleared even if destroy is async
      console.log("User logged out, session destroyed.");
      return res.status(200).json({ message: "Logout successful" }); // Send success confirmation
    });
  });
});

// --- End Authentication Routes ---


// --- Protected API Routes ---

// Example protected route requiring ADMIN role
app.get('/api/dashboard/check-ins',
  adminRateLimiter, // Apply rate limiting first
  requireRole(Role.ADMIN), // Then check role
  getCheckInsController
);

// Mount other client-related API routes under '/api'
// These require at least VOLUNTEER role and have staff rate limiting
app.use('/api',
  staffRateLimiter,
  requireRole(Role.VOLUNTEER),
  clientRoutes // Assuming clientRoutes contains handlers for /api/clients, etc.
);

// --- End Protected API Routes ---


// --- Central Error Handling Middleware ---
// This should be defined LAST, after all other app.use() and routes
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[Unhandled Error]', err);
  // Avoid leaking stack traces in production responses
  const responseError = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message || 'Internal server error'; // Show more detail in dev

  // If headers already sent, delegate to default Express handler
  if (res.headersSent) {
    return next(err);
  }

  // Respond with a generic error status and message
  res.status(500).json({ error: responseError });
});
// --- End Central Error Handling Middleware ---


// --- Graceful Shutdown Logic ---
const gracefulShutdown = async (signal: string) => {
  console.log(`Received ${signal}. Closing server and Redis connection...`);
  // Add server closing logic if running locally
  // server.close(() => { ... }); // Requires capturing the server instance from app.listen

  try {
    if (redisClient.isReady) {
      await redisClient.quit();
      console.log('Redis connection closed.');
    } else {
      console.log('Redis client not connected or already closing.');
    }
    process.exit(0); // Exit cleanly
  } catch (err) {
    console.error('Error during graceful shutdown:', err);
    process.exit(1); // Exit with error code
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT')); // Ctrl+C
process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // Kill command
// --- End Graceful Shutdown Logic ---

			   
									  
						
												
																
   

// --- Server Start (for local development) ---
// Ensure this block doesn't run in serverless environments like Vercel
if (process.env.NODE_ENV !== 'production' && process.env.VERCEL !== '1') {
  const PORT = process.env.PORT || 3001; // Use a different default? 5000 often used by React dev servers
  const server = app.listen(PORT, () => { // Capture server instance
    console.log(`\n🚀 Server running locally on port ${PORT}`);
    console.log(`   Redis client connected: ${redisClient.isReady}`);
    console.log(`   Allowed Origins: ${allowedOrigins.join(', ')}`);
    console.log(`   Client URL: ${V_CLIENT_URL}`);
    console.log(`Press CTRL+C to stop\n`);
  });

  // Add server closing to graceful shutdown for local dev
  const localGracefulShutdown = async (signal: string) => {
      console.log(`Received ${signal}. Closing local server and Redis connection...`);
      server.close(async () => { // Close HTTP server first
          console.log('HTTP server closed.');
          try {
              if (redisClient.isReady) {
                  await redisClient.quit();
                  console.log('Redis connection closed.');
              } else {
                  console.log('Redis client not connected or already closing.');
              }
              process.exit(0);
          } catch (err) {
              console.error('Error closing Redis connection during shutdown:', err);
              process.exit(1);
          }
      });
  };
  process.off('SIGINT', gracefulShutdown); // Remove generic handler
  process.off('SIGTERM', gracefulShutdown); // Remove generic handler
  process.on('SIGINT', () => localGracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => localGracefulShutdown('SIGTERM'));

}
// --- End Server Start ---


// --- Vercel Serverless Function Export ---
// This is the entry point for Vercel invocations
export default async (req: express.Request, res: express.Response) => {
  // Ensure Redis is connected on cold starts (important for serverless)
  if (!redisClient.isReady) {
    try {
      console.warn('Redis client not ready on Vercel invocation. Attempting to connect...');
      await redisClient.connect();
      console.log('Redis reconnected successfully.');
    } catch (err) {
      console.error('FATAL: Failed to reconnect Redis on Vercel function invocation:', err);
      // Depending on requirements, you might:
      // 1. Fail the request: return res.status(500).json({ error: "Session service unavailable" });
      // 2. Proceed without session persistence (users might get logged out): console.warn('Proceeding without Redis connection.');
      // For now, let's fail the request as sessions are critical
      return res.status(503).json({ error: "Session service temporarily unavailable. Please try again later." });
    }
  }
  // Process the request using the configured Express app
  await app(req, res);
};
// --- End Vercel Serverless Function Export ---
