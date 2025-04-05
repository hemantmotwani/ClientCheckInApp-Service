import { Request, Response, NextFunction } from 'express';
// import { auth } from '../config/firebase';

// export const authenticateUser = async (req: Request, res: Response, next: NextFunction) => {
//   try {
//     const authHeader = req.headers.authorization;
//     if (!authHeader?.startsWith('Bearer ')) {
//       return res.status(401).json({ error: 'Unauthorized' });
//     }

//     const token = authHeader.split('Bearer ')[1];
//     const decodedToken = await auth.verifyIdToken(token);
//     req.user = decodedToken;
//     next();
//   } catch (error) {
//     console.error('Error in authenticateUser:', error);
//     res.status(401).json({ error: 'Unauthorized' });
//   }
// };

// export const requireAdmin = async (req: Request, res: Response, next: NextFunction) => {
//   try {
//     const user = req.user;
//     if (!user || user.role !== 'admin') {
//       return res.status(403).json({ error: 'Forbidden' });
//     }
//     next();
//   } catch (error) {
//     console.error('Error in requireAdmin:', error);
//     res.status(403).json({ error: 'Forbidden' });
//   }
// }; 