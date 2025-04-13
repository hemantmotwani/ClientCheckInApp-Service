import rateLimit from 'express-rate-limit';

export const adminRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, 
  message: 'Too many requests from this IP. Please try after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false, 
});

export const staffRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, 
  message: 'Too many requests from this IP. Please try after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false, 
});