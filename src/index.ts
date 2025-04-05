import dotenv from 'dotenv';
// Load environment variables first
dotenv.config();

import express from 'express';
import cors from 'cors';
import clientRoutes from './routes/clientRoutes';

const app = express();
const port = process.env.PORT || 3001;
console.log("Client_url", process.env.CLIENT_URL);
// CORS configuration
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://client-checkin-app.vercel.app',
    'https://*.vercel.app',
    '*',
    process.env.CLIENT_URL || 'http://localhost:5173'
  ].filter(Boolean),
  credentials: true
}));

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

// Start server
// app.listen(port, () => {
//   console.log('=================================');
//   console.log(`[Server] Starting up...`);
//   console.log(`[Server] Environment: ${process.env.NODE_ENV || 'development'}`);
//   console.log(`[Server] Port: ${port}`);
//   console.log(`[Server] CORS: Enabled (allowing all origins in development)`);
//   console.log(`[Server] Firebase Project: ${process.env.FIREBASE_PROJECT_ID}`);
//   console.log('=================================');
// }); 
// export default app;
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