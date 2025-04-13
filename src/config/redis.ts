// src/config/redis.ts
import { createClient } from 'redis';
import { RedisStore} from 'connect-redis';
import session from 'express-session'; // Needed for SessionOptions type if used

console.log('Initializing Redis configuration...');

// --- Initialize Redis Client ---
console.log('Attempting to create Redis client...');
console.log(`Using Redis URL: ${process.env.KV_URL ? 'KV_URL' : process.env.REDIS_URL ? 'REDIS_URL' : 'Not specified'}`);

// Prioritize Vercel KV_URL, then generic REDIS_URL
const redisUrl = process.env.KV_URL || process.env.REDIS_URL;

if (!redisUrl) {
  console.error('FATAL: Redis URL (KV_URL or REDIS_URL) is not defined in environment variables.');
  // Consider throwing an error or exiting if Redis is essential
  // throw new Error('Redis URL not configured');
}

export const redisClient = createClient({
  url: redisUrl, // Use the determined URL
});

// --- Handle Redis Client Connection Events ---
redisClient.on('error', (err) => console.error('Redis Client Error:', err));
redisClient.on('connect', () => console.log('Redis client attempting to connect...'));
redisClient.on('ready', () => console.log('Redis client connected successfully and ready to use.'));
redisClient.on('end', () => console.log('Redis client connection closed.'));
redisClient.on('reconnecting', () => console.log('Redis client attempting to reconnect...'));

// --- Connect the Redis client ---
// Important: Connect the client. The application startup depends on this.
redisClient.connect().catch(err => {
    console.error('Failed to connect Redis client:', err);
    // Optionally exit if connection is critical for startup
    // process.exit(1);
});

console.log('Redis client connection initiated.');

// --- Initialize Redis Session Store ---
export const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'sess:', // Optional: prefix for session keys in Redis
  // ttl: 86400 // Optional: session time-to-live in seconds (default is 1 day)
});

console.log('Redis session store initialized.');

