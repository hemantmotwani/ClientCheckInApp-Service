import { getClient } from '../../services/clientService';
// import { db } from '../../config/firebase';
import { Database } from 'firebase-admin/database';

// describe('Client Service Integration Tests', () => {
//   const testBarcode = 'TEST123';
//   const testClient = {
//     name: 'Test User',
//     barcode: testBarcode,
//     email: 'test@example.com'
//   };

//   beforeAll(async () => {
//     // Set up test data
//     const clientRef = db.ref(`Client_Details/${testBarcode}`);
//     await clientRef.set(testClient);
//   });

//   afterAll(async () => {
//     // Clean up test data
//     const clientRef = db.ref(`Client_Details/${testBarcode}`);
//     await clientRef.set(null);
//   });

//   it('should fetch client data by barcode', async () => {
//     // Act
//     const result = await getClient(testBarcode);

//     // Assert
//     expect(result).not.toBeNull();
//     expect(result).toHaveProperty('id', testBarcode);
//     expect(result).toHaveProperty('name', testClient.name);
//     expect(result).toHaveProperty('barcode', testClient.barcode);
//     expect(result).toHaveProperty('email', testClient.email);
//   });

//   it('should return null for non-existent barcode', async () => {
//     // Act
//     const result = await getClient('NONEXISTENT123');

//     // Assert
//     expect(result).toBeNull();
//   });

//   it('should handle invalid barcode format', async () => {
//     // Act & Assert
//     await expect(getClient('')).rejects.toThrow();
//   });
// }); 