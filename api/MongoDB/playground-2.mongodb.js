/* global use, db */
// MongoDB Playground
// Use Ctrl+Space inside a snippet or a string literal to trigger completions.

const database = 'COE817';
const collection = 'Users';

// Select the database to use.
use(database);

// 1. Create a new collection with schema validation for constraints.
db.createCollection(collection, {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['fullname', 'username', 'password', 'email'],
      properties: {
        fullname: {
          bsonType: 'string',
          description: 'must be a string and is required'
        },
        username: {
          bsonType: 'string',
          description: 'must be a string and is required'
        },
        email: {
          bsonType: 'string',
          description: 'must be a string and is required'
        },
        password: {
          bsonType: 'string',
          description: 'must be binary data for a password hash and is required'
        }
      }
    }
  }
});

// 2. Ensure unique index on 'username' to act as a primary key.
db.getCollection(collection).createIndex({ username: 1 }, { unique: true });

// 3. Insert a sample document to verify constraints (for testing purposes).
try {
  db.getCollection(collection).insertOne({
    fullname: 'Sample Smith',
    username: 'sampleUser',
    email: 'stansmith@gmail.com',
    password: 'hash' 
  });
  db.getCollection(collection).insertOne({
    fullname: 'Gustavo Fring',
    username: 'Gus',
    email:'fring@hotmail.com',
    password:'2b$12$eHc/yYEE9NCA1V3F9toJjuwgHTgfnLI9wSLkrNIwlbAPzZg6FXu3q'//password is blue
  });
  console.log('Collection created with constraints, and sample data inserted successfully.');
} catch (error) {
  console.error('Error inserting sample data:', error.message);
}
