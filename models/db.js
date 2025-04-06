require('dotenv').config(); // зарежда променливи от .env
const mysql = require('mysql2');

const connection = mysql.createConnection(
    process.env.MYSQL_URL || {
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'travelwisedb'
    }
);


connection.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed: ' + err.stack);
        return;
    }
    console.log('✅ Connected to Railway MySQL');
});

module.exports = connection;
