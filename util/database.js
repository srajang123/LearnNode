const mysql = require('mysql2');
const pool = mysql.createPool({
    host: '127.0.0.1',
    user: 'srajan',
    password: 'Project@123',
    database: 'node'
});
module.exports = pool.promise();