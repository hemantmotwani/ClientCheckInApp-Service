export interface Client {
  id: string;
  name: string;
  barcode: string;
  status: string;
}

export interface CheckInRecord {
  id: string;
  clientId: string;
  barcode: string;
  timestamp: string;
  status: string;
}

export interface User {
  uid: string;
  email: string;
  role: 'admin' | 'volunteer';
} 