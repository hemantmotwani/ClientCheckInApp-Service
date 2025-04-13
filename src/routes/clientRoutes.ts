import { Router } from 'express';
import { getClientController, checkInClientController } from '../controllers/clientController';

const router = Router();

// All routes are public
// router.get('/dashboard/check-ins', getCheckInsController);
router.get('/clients/:barcode', getClientController);
router.post('/check-in', checkInClientController);

export default router; 