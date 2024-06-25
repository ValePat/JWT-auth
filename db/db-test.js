const mysql = require('mysql2/promise');
require('dotenv').config(); // Carica le variabili d'ambiente dal file .env

// Creazione della connessione al database
const pool  = mysql.createPool({
    host: 'sql7.freesqldatabase.com',
    user: 'sql7715739',
    password: 'T2jcFFSa9v',
    database: 'sql7715739'
});

// Esempio di query
async function testDatabaseConnection() {
    try {
      // Get a connection from the pool
      const connection = await pool.getConnection();
  
      // Execute a query
      const [rows, fields] = await connection.query('SELECT * FROM Contacts');
  
      // Output the query result
      console.log('Query result:', rows);
  
      // Release the connection back to the pool
      connection.release();
    } catch (error) {
      console.error('Failed to query the database:', error.message);
      throw error;
    } finally {
      // End the pool when done
      pool.end();
    }
  }
  
  testDatabaseConnection();
