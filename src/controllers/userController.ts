// Example: src/controllers/userController.ts
import { Request, Response } from 'express';

// Helper function to attempt splitting name (adjust as needed)

export const getUserProfile = (req: Request, res: Response) => {
    // req.user is populated by the verifyFirebaseToken middleware
    const firebaseUser = req.user;

    if (!firebaseUser) {
        // This shouldn't happen if verifyFirebaseToken is applied correctly
        return res.status(401).json({ error: 'Unauthorized', message: 'User data not found in request.' });
    }

    // Extract information
    const firstName = firebaseUser.firstName
    const lastName  = firebaseUser.lastName;
    const roles = firebaseUser.roles || []; // Get roles attached by middleware
    const email = firebaseUser.email;
    const uid = firebaseUser.uid; // Firebase unique ID
    const activeRole = firebaseUser.activeRole;
    let name = '';
    // Add firstName if it exists
    if (firstName) {
        name += firstName;
    }
    // Add lastName if it exists, adding a space only if firstName also existed
    if (lastName) {
        name += (name.length > 0 ? ' ' : '') + lastName;
    }
    // Trim any potential leading/trailing whitespace (though unlikely with this logic)
    name = name.trim();
    // If name is still empty after trying, maybe use email as a fallback or leave empty
    if (!name && email) {
        name = email; // Optional: fallback to email if name parts are missing
    }
    // 
    // Construct the profile response
    const userProfile = {
        uid,
        email,
        name,
        roles,
        activeRole,
        // You could add other relevant fields from firebaseUser if needed
        // picture: firebaseUser.picture,
    };

    console.log(`Responding with profile for user: ${uid}`);
    res.status(200).json(userProfile);
};
