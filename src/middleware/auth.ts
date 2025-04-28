// src/middleware/auth.ts
import { Request, Response, NextFunction } from "express";
import { Role } from '../types/roles'; // Adjust path if needed
import { auth, db } from '../config/firebase';
import { DecodedIdToken } from 'firebase-admin/auth';
import { Timestamp } from 'firebase-admin/firestore'; // Import Timestamp for explicit typing

const splitName = (fullName?: string): { firstName?: string, lastName?: string } => {
    if (!fullName) {
        return { firstName: undefined, lastName: undefined };
    }
    const parts = fullName.trim().split(' ');
    const firstName = parts[0];
    const lastName = parts.length > 1 ? parts.slice(1).join(' ') : undefined;
    return { firstName, lastName };
};
// --- Helper Functions (Copied from index.ts or imported if extracted) ---
// It might be better to move these helpers to a dedicated 'utils' file
// if they are needed in multiple places. For now, let's keep them here.
// const getRoles = (email: string): Role[] => {
//     const adminEmails = process.env.ADMIN_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
//     const staffEmails = process.env.STAFF_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];
//     const volunteerEmails = process.env.VOLUNTEER_EMAILS?.split(',').map(e => e.trim().toLowerCase()) || [];

//     const assignedRoles: Set<Role> = new Set();
//     const lowerCaseEmail = email.toLowerCase();

//     if (adminEmails.includes(lowerCaseEmail)) {
//         assignedRoles.add(Role.ADMIN); assignedRoles.add(Role.STAFF); assignedRoles.add(Role.VOLUNTEER);
//     } else if (staffEmails.includes(lowerCaseEmail)) {
//         assignedRoles.add(Role.STAFF); assignedRoles.add(Role.VOLUNTEER);
//     } else if (volunteerEmails.includes(lowerCaseEmail)) {
//         assignedRoles.add(Role.VOLUNTEER);
//     }
//     return Array.from(assignedRoles);
// };

const determineDefaultActiveRole = (roles: Role[]): Role | undefined => {
    if (roles.includes(Role.ADMIN)) return Role.ADMIN;
    if (roles.includes(Role.STAFF)) return Role.STAFF;
    if (roles.includes(Role.VOLUNTEER)) return Role.VOLUNTEER;
    return undefined;
};
// --- End Helper Functions ---


// --- Firebase Authentication Middleware ---
export const verifyFirebaseToken = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    console.log("Verifying Firebase Token - Auth Header:", authHeader ? 'Present' : 'Missing');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log("No Bearer token found in Authorization header.");
        // Consistent error format
        return res.status(401).json({ error: 'Unauthorized', message: 'No token provided.' });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
        console.log("Attempting to verify Firebase ID token using imported auth service...");
        const decodedToken = await auth.verifyIdToken(idToken);
        console.log("Firebase ID token verified successfully. UID:", decodedToken.uid);

        // Attach user info and roles to request
        const email = decodedToken.email; // Ensure email exists for Firestore key
        const uid = decodedToken.uid; // Get UID early
        const userFromRequest = decodedToken as Express.Request['user'];

        if (!email) {
            console.error(`Authentication successful for UID ${uid}, but email is missing. Access denied.`);
            return res.status(403).json({ error: 'Forbidden', message: 'User email is required but missing.' });
        }

        let userRoles: Role[] = []; // Default to no roles
        let userData;
        // if (userWithRoles) {
        //     if (decodedToken.email) {
        //         userWithRoles.roles = getRoles(decodedToken.email);
        //         userWithRoles.activeRole = determineDefaultActiveRole(userWithRoles.roles);
        //     } else {
        //         userWithRoles.roles = [];
        //     }
        //     req.user = userWithRoles;
       

        // console.log("User attached to request:", { uid: req.user?.uid, email: req.user?.email, roles: req.user?.roles });

         // --- Firestore Profile Sync ---
         try {
            console.log(`Fetching Firestore profile for email: ${email}`);
            const usersCollection = db.collection('users'); // Or your preferred collection name
            const userDocRef = usersCollection.doc(email); // Use email as document ID

            // const { firstName, lastName } = splitName(decodedToken.name);
            const userDoc = await userDocRef.get();

            if (!userDoc.exists) {
                // *** FAIL if profile does not exist ***
                console.warn(`Access Denied: No Firestore profile found for email ${email} (UID: ${uid}). User must be registered in the 'users' collection.`);
                return res.status(403).json({ error: 'Forbidden', message: 'User profile not found.' });
            }
            
                userData = userDoc.data();
                // Ensure roles field exists and is an array, otherwise default to empty
                userRoles = Array.isArray(userData?.roles) ? userData?.roles : [];
                console.log(`Found existing user profile. Roles from Firestore: ${userRoles}`);

        }catch (firestoreError) {
            // Log the error but don't necessarily block the API request
            console.error(`Error fetching user profile from Firestore for ${email}:`, firestoreError);
            return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to retrieve user profile.' });
        }

        // --- Attach User Info to Request ---
        // User profile exists, so we can safely attach info
        if (userFromRequest && userData) {
            userFromRequest.roles = userRoles;
            userFromRequest.activeRole = determineDefaultActiveRole(userRoles);
            userFromRequest.email = userData.email;
            userFromRequest.firstName = userData.firstName;
            userFromRequest.lastName = userData.lastName;
            req.user = userFromRequest;
            console.log("User attached to request:", { uid: req.user?.uid, email: req.user?.email, roles: req.user?.roles });
        }
        // --- End Attach User Info ---

        // --- End Firestore Profile Sync ---
        // --- Firestore Login Tracking (loginHistory Collection) ---
        // --- Attach User Info to Request ---
        try {
            console.log(`Recording login event to 'loginHistory' for UID: ${uid}`);
            const loginHistoryCollection = db.collection('loginHistory');

            const loginData = {
                uid: uid, // User identifier
                email: email , // Include email if available, otherwise null
                loginTime: Timestamp.now(), // Use Firestore Timestamp for consistency
                ipAddress: req.ip,
                userAgent: req.headers['user-agent']
            };

            // Use add() to create a new document with an auto-generated ID for each login
            const docRef = await loginHistoryCollection.add(loginData);
            console.log(`Login event recorded successfully with ID: ${docRef.id}`);

        } catch (firestoreError) {
            console.error(`Error recording login event to 'loginHistory' for UID ${uid}:`, firestoreError);
            // Log the error, but usually don't block the request for this
        }
        // --- End Firestore Login Tracking ---

     
        next();
    } catch (error: any) {
        console.error("Firebase token verification failed:", error.message);
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).json({ error: 'Unauthorized', message: 'Token expired.' });
        }
        // Provide a slightly more specific error for invalid tokens
        return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or malformed token.' });
    }
};
// --- End Firebase Authentication Middleware ---

// --- RBAC Middleware ---
export const requireFirebaseRole = (requiredRole: Role) => {
    return (req: Request, res: Response, next: NextFunction) => {
        // Ensure user object and roles array exist before checking
        if (!req.user?.roles?.includes(requiredRole)) {
            console.warn(`Authorization Failed: User ${req.user?.uid || '(no user)'} lacks required role '${requiredRole}'. User roles: ${req.user?.roles}`);
            return res.status(403).json({ error: 'Forbidden', message: `Requires ${requiredRole} role.` });
        }
        console.log(`Authorization Success: User ${req.user.uid} has required role '${requiredRole}'.`);
        next();
    };
};
// --- End RBAC Middleware ---

