const express = require('express');
const dotenv = require('dotenv');
dotenv.config();
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const nodeFetch = require('node-fetch');
const fetch = nodeFetch.default || nodeFetch;

const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const app = express();

const saltRounds = 10; 

// A07:2021 Identification and Authentication Failures
app.use(session({
    secret: process.env.SESSION_KEY, 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
    } 
}));

// A07:2021 Identification and Authentication Failures
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { 
        error: 'Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 15 minut.',
        userId: null
    },
});

app.use(morgan('dev'));

app.set('view engine', 'ejs');
app.set('views', './views');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

const port = process.env.PORT || 3000;

// A05:2021 – Security Misconfiguration
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// A05:2021 – Security Misconfiguration
const dbUnsecure = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'owasp'
});


app.use(express.static('dist'));

db.connect(err => {
    if (err) {
        console.error('Błąd połączenia z bazą MySQL: ', err.stack);
        console.error('Sprawdź, czy XAMPP jest uruchomiony, a dane w .env są poprawne.');
        return;
    }
    console.log('✅ Połączono z MySQL jako id ' + db.threadId);

    db.query(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME}`, (err) => {
        if (err) throw err;
        db.changeUser({ database: process.env.DB_NAME }, async (err) => { 
            if (err) throw err;

            const createUsersSecure = `
                CREATE TABLE IF NOT EXISTS users_secure (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user VARCHAR(255) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NULL,
                    surname VARCHAR(255) NULL,
                    role VARCHAR(50) DEFAULT 'user'
                );
            `;
            db.query(createUsersSecure, (err) => {
                if (err) throw err;
                console.log('Tabela "users_secure" sprawdzona/utworzona.');
            });
        });
    });
});

dbUnsecure.connect(err => {
    if (err) {
        console.error('Błąd połączenia z bazą MySQL: ', err.stack);
        console.error('Sprawdź, czy XAMPP jest uruchomiony, a dane w .env są poprawne.');
        return;
    }
    console.log('✅ Połączono z MySQL jako id ' + db.threadId);

    dbUnsecure.query(`CREATE DATABASE IF NOT EXISTS owasp`, (err) => {
        if (err) throw err;
        dbUnsecure.changeUser({ database: process.env.DB_NAME }, async (err) => { 
            if (err) throw err;
            const createUsersUnsecure = `
                CREATE TABLE IF NOT EXISTS users_unsecure (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user VARCHAR(255) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NULL,
                    surname VARCHAR(255) NULL,
                    role VARCHAR(50) DEFAULT 'user'
                );
            `;
            dbUnsecure.query(createUsersUnsecure, (err) => {
                if (err) throw err;
                console.log('Tabela "users_unsecure" sprawdzona/utworzona.');
            });
        });
    });
});

const secureRoutes = require('./routes/secure-paths');
const unsecureRoutes = require('./routes/unsecure-paths');

app.use('/', secureRoutes({ db, loginLimiter, saltRounds, fetch }));
app.use('/', unsecureRoutes({ dbUnsecure, saltRounds }));

app.get('/', (req, res) => {
    const userId = req.session.userId;
    res.render("index.ejs", { userId: userId });
});

app.listen(port, () => {
    console.log(`🚀 Serwer działa na http://localhost:${port}`);
    console.log(`Podatne A01: http://localhost:${port}/vulnerable/a01?id=1`);
});