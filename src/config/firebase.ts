import { initializeApp, cert } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { getAuth } from 'firebase-admin/auth';
import admin from 'firebase-admin';
import * as dotenv from 'dotenv'
dotenv.config();

import firebaseAdmin from 'firebase-admin';


// Debug logs for environment variables
console.log('Checking Firebase environment variables:');
console.log('FIREBASE_PROJECT_ID:', process.env.FIREBASE_PROJECT_ID);
console.log('FIREBASE_PRIVATE_KEY_ID:', process.env.FIREBASE_PRIVATE_KEY_ID);
console.log('FIREBASE_CLIENT_EMAIL:', process.env.FIREBASE_CLIENT_EMAIL);
console.log('FIREBASE_CLIENT_ID:', process.env.FIREBASE_CLIENT_ID);
console.log('FIREBASE_DATABASE_URL:', process.env.FIREBASE_DATABASE_URL);

if (!process.env.FIREBASE_PROJECT_ID) {
  throw new Error('FIREBASE_PROJECT_ID is not defined in environment variables');
}

if (!process.env.FIREBASE_DATABASE_URL) {
  throw new Error('FIREBASE_DATABASE_URL is not defined in environment variables');
}

const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
  databaseURL: process.env.FIREBASE_DATABASE_URL
};

// Log the project ID to verify it's being loaded
console.log('Initializing Firebase with project ID:', process.env.FIREBASE_PROJECT_ID);
if (!firebaseAdmin.apps.length) {
  firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert(serviceAccount as any),
  });
}

// const app = initializeApp({
//   credential: cert(serviceAccount as any),
//   databaseURL: process.env.FIREBASE_DATABASE_URL
// });

console.log(' Firebase DB initialized');

export const db = firebaseAdmin.firestore();
// export const auth = getAuth(app); 