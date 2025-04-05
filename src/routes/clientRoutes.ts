import { Router } from 'express';
import { getClientController, checkInClientController, getCheckInsController } from '../controllers/clientController';

const router = Router();

// All routes are public
router.get('/check-ins', getCheckInsController);
router.get('/clients/:barcode', getClientController);
router.post('/check-in', checkInClientController);

export default router; 