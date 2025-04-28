import { initializeApp, cert } from 'firebase-admin/app';
// import { getDatabase } from 'firebase-admin/database';
import { getFirestore } from 'firebase-admin/firestore'; // Use getFirestore
import { getAuth } from 'firebase-admin/auth';
import admin from 'firebase-admin';
import * as dotenv from 'dotenv'
import { App } from 'firebase-admin/app';

dotenv.config();

import firebaseAdmin from 'firebase-admin';


// Debug logs for environment variables
console.warn('Checking Firebase environment variables:');
console.warn('FIREBASE_PROJECT_ID:', process.env.FIREBASE_PROJECT_ID);
console.warn('FIREBASE_PRIVATE_KEY_ID:', process.env.FIREBASE_PRIVATE_KEY_ID);
console.warn('FIREBASE_CLIENT_EMAIL:', process.env.FIREBASE_CLIENT_EMAIL);
console.warn('FIREBASE_CLIENT_ID:', process.env.FIREBASE_CLIENT_ID);
console.warn('FIREBASE_DATABASE_URL:', process.env.FIREBASE_DATABASE_URL);

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

let app: App; // Declare app variable


// Log the project ID to verify it's being loaded
console.log('Initializing Firebase with project ID:', process.env.FIREBASE_PROJECT_ID);
if (!firebaseAdmin.apps.length) {
  console.log('Initializing Firebase Admin SDK...');
  app = firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert(serviceAccount as admin.ServiceAccount),
    // databaseURL: process.env.FIREBASE_DATABASE_URL // Only if using Realtime DB
  });
  console.log('Firebase Admin SDK initialized successfully.');
} else {
  console.log('Firebase Admin SDK already initialized.');
  app = firebaseAdmin.app(); // Get the default app
}


console.log('Exporting Firebase services...');
export const db = getFirestore(app); 
export const auth = getAuth(app); 
console.log('Firebase services (db, auth) ready for export.');