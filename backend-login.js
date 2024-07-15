const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Hemanth',
    database: 'registration'
});

db.connect((err) => {
    if (err) {
        throw err;
    }
    else{
        console.log("MySQL connected...");
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static('public'));
app.post('/register', (req, res) => {
    const { name, email, pass, confirmPass } = req.body; // Include confirmPass

    if (!name || !email || !pass || !confirmPass) {
        return res.status(400).send('All fields are required');
    }
    const checkEmailSql = 'SELECT * FROM userinfo WHERE mail = ?';
    db.query(checkEmailSql, [email], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            return res.status(400).send('Email already exists');
        }
    if (pass !== confirmPass) {
        return res.status(400).send('Passwords do not match');
    }
    bcrypt.hash(pass, 10, (err, hash) => {
        if (err) throw err;
        const sql = 'INSERT INTO userinfo (name, mail, pass) VALUES (?, ?, ?)';
        db.query(sql, [name, email, hash], (err, result) => {
            if (err) throw err;
            res.send('User registered...');
        });
    });
});
});


app.post('/login', (req, res) => {
    const { email, pass } = req.body;
    if (!email || !pass) {
        return res.status(400).send('All fields are required');
    }
    const sql = 'SELECT * FROM userinfo WHERE mail = ?';
    db.query(sql, [email], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(pass, user.pass, (err, isMatch) => {
                if (err) throw err;
                if (isMatch) {
                    res.send('Login successful');
                } else {
                    res.send('Invalid credentials');
                }
            });
        } else {
            res.send('Invalid credentials');
        }
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
