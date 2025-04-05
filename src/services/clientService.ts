import { db } from '../config/firebase';

interface Client {
  id: string;
  first_name: string;
  last_name: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  postal: string;
  dob: string;
  ltf_id: string;
  client_id: string;
  last_visit: string;
  updated_at: string;
}

interface CheckIn {
  id: string;
  client_id: string;
  ltf_id: string;
  first_name: string;
  last_name: string;
  address: string;
  city: string;
  state: string;
  postal: string;
  phone: string;
  email: string;
  checkInTime: string;
}

export const getClient = async (clientId: string): Promise<any | null> => {
  try {
    console.log(`[Database] Searching for Client: ${clientId}`);

    const clientRef = db.collection('Client_Details').doc(clientId);
    const clientDoc = await clientRef.get();
    if (!clientDoc.exists) {
      console.log(`[Database] No client found with barcode: ${clientId}`);
      return null;
    } 
    return clientDoc.data();
  } catch (error) {
    console.error('Error getting client:', error);
    throw error;
  }
};

export const checkInClient = async (barcode: string) => {
  try {
    console.log(`[Database] Starting check-in process for barcode: ${barcode}`);
    
    // Get client data
    const client = await getClient(barcode);
    if (!client) {
      console.log(`[Database] Check-in failed: Client not found with barcode ${barcode}`);
      throw new Error('Client not found');
    }

    // Create check-in record with timestamp as key for natural ordering
    const timestamp = new Date().toISOString();
    console.log("timestamp", timestamp)
    const client_checkin_data = {
      checkin_Id: client['client_id'] + "" + Date.now(),
      client_Id: client['client_id'],
      ltf_Id: client['ltf_id'],
      checkin_time: Date.now()      
    };

    console.log(`[Database] Creating check-in record: ${JSON.stringify(client_checkin_data, null, 2)}`);
    await db.collection('Client_CheckIns').doc(client_checkin_data.client_Id).set(client_checkin_data);    
    // const checkInsRef = db.ref('checkIns');
    // await checkInsRef.child(timestamp).set(checkInData);
    
    console.log(`[Database] Check-in successful. Timestamp: ${timestamp}`);
    return { id: client_checkin_data.checkin_Id, ...client_checkin_data };
  } catch (error) {
    console.error('[Database Error] Failed to check in client:', error);
    throw error;
  }
};

export const getAllCheckIns = async (): Promise<CheckIn[]> => {
  try {
    console.log(`[Database] Fetching all check-ins`);
    const checkInsRef = db.collection('Client_CheckIns');
    const querySnapshot = await checkInsRef
      .orderBy('checkin_time', 'desc')
      .limit(100)
      .get();
    
    const checkIns: CheckIn[] = [];
    const clientDetailsMap: { [key: string]: any } = {};

    for (const doc of querySnapshot.docs) {
      const checkInData = doc.data();
      const clientId = checkInData['client_Id'];
      // Fetch client details if not already fetched
      if (!clientDetailsMap[clientId]) {
        try {
          const clientData = await getClient(clientId);
          if (clientData) {
            clientDetailsMap[clientId] = clientData;
          }
        } catch (error) {
          console.error(`Error fetching client details for ID ${clientId}:`, error);
        }
      }
      console.log(`[Database] Client details: ${JSON.stringify(clientDetailsMap, null, 2)}`);
      const clientData = clientDetailsMap[clientId] || {};

      checkIns.push({
        id: doc.id,
        client_id: checkInData['client_Id'] || '',
        ltf_id: checkInData['ltf_Id'] || '',
        first_name: clientData.first_name || '',
        last_name: clientData.last_name || '',
        address: clientData.address || '',
        city: clientData.city || '',
        state: clientData.state || '',
        postal: clientData.postal || '',
        phone: clientData.phone || '',
        email: clientData.email || '',
        checkInTime: checkInData.checkin_time,
      });
    }

    return checkIns;
  } catch (error) {
    console.error('Error getting check-ins:', error);
    throw error;
  }
}; 