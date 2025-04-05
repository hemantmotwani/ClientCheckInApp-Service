import { Request, Response } from 'express';
import { getClient, checkInClient, getAllCheckIns } from '../services/clientService';

export const getClientController = async (req: Request, res: Response) => {
  try {
    const { barcode } = req.params;
    console.log(`[Controller] Getting client with barcode: ${barcode}`);
    
    const client = await getClient(barcode);
    
    if (!client) {
      console.log(`[Controller] Client not found with barcode: ${barcode}`);
      return res.status(404).json({ error: 'Client not found' });
    }
    
    console.log(`[Controller] Successfully retrieved client: ${JSON.stringify(client, null, 2)}`);
    res.json(client);
  } catch (error) {
    console.error('[Controller Error] Failed to get client:', error);
    res.status(500).json({ error: 'Failed to get client' });
  }
};

export const checkInClientController = async (req: Request, res: Response) => {
  try {
    const { barcode } = req.body;
    console.log(`[Controller] Processing check-in for barcode: ${barcode}`);
    
    if (!barcode) {
      console.log('[Controller] Check-in failed: No barcode provided');
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const checkIn = await checkInClient(barcode);
    console.log(`[Controller] Successfully checked in client: ${JSON.stringify(checkIn, null, 2)}`);
    res.status(201).json(checkIn);
  } catch (error) {
    console.error('[Controller Error] Failed to check in client:', error);
    res.status(500).json({ error: 'Failed to check in client' });
  }
};

export const getCheckInsController = async (req: Request, res: Response) => {
  try {
    console.log('[Controller] Fetching all check-ins');
    const checkIns = await getAllCheckIns();
    
    console.log(`[Controller] Successfully retrieved ${checkIns.length} check-ins`);
    res.json(checkIns);
  } catch (error) {
    console.error('[Controller Error] Failed to get check-ins:', error);
    res.status(500).json({ error: 'Failed to get check-ins' });
  }
}; 