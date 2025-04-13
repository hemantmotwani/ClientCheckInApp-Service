// src/middleware/rbac.ts
import { Role } from '../types/roles';
import { Request, Response, NextFunction } from 'express';

export const requireRole = (role: Role) => {
  return (req: Request, res: Response, next: NextFunction) => {
    console.log(`[RBAC] Checking for role: ${role}`);
    console.log(`[RBAC] Is authenticated: ${req.isAuthenticated()}`); // Check authentication status
    console.log(`[RBAC] req.user:`, req.user); // Log the entire user object

    if (!req.user?.roles.includes(role)) {
      console.error(`[RBAC] Forbidden: User roles ${JSON.stringify(req.user?.roles)} do not include required role ${role}`);
      return res.status(403).json({ error: 'Forbidden' });
    }
    console.log(`[RBAC] Access granted for role: ${role}`);

    next();
  };
};