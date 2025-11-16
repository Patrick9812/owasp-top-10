const express = require('express');
const dotenv = require('dotenv');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
dotenv.config();

const saltRounds = 10; 

app.use(session({
    secret: process.env.SESSION_KEY, 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
    } 
}));

app.set('view engine', 'ejs');
app.set('views', './views');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

const port = process.env.PORT || 3000;

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
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
            db.query(createUsersUnsecure, (err) => {
                if (err) throw err;
                console.log('Tabela "users_unsecure" sprawdzona/utworzona.');
            });
        });
    });
});

app.get('/', (req, res) => {
    const userId = req.session.userId;
    res.render("index.ejs", { userId: userId });
});

app.get('/register', (req, res) => {
    const userId = req.session.userId; 
    res.render("register.ejs", { userId: userId });
});

app.get('/main-logged-page/:id', (req, res) => {
    const requestedId = req.params.id; 
    const loggedInId = req.session.userId;

    if (!loggedInId) {
        return res.redirect('/login');
    }

    const sql = 'SELECT id, user, name, surname, role FROM users_secure WHERE id = ?';

    db.query(sql, [requestedId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).render('error.ejs', { 
                message: `Nie znaleziono użytkownika o ID: ${requestedId}`,
                userId: loggedInId
            });
        }

        const userData = results[0];

        res.render("main-logged-page.ejs", { 
            userId: loggedInId, 
            requestedId: requestedId,
            userData: userData
        });
    });
});

app.get('/main-logged-page-secure/:id', (req, res) => {
    const userIdFromSession = req.session.userId;
    const userIdFromUrl = parseInt(req.params.id); 

    if (!userIdFromSession) {
        return res.redirect('/login');
    }

    if (userIdFromSession !== userIdFromUrl) {
        return res.status(403).send('Brak uprawnień. Możesz przeglądać tylko swój profil.')
    }
    const sql = 'SELECT id, user, name, surname, role FROM users_secure WHERE id = ?';

    db.query(sql, [userIdFromSession], (err, results) => { 
        if (err || results.length === 0) {
            return res.status(500).render('error.ejs', { 
                message: `Błąd serwera: Nie można pobrać danych konta ${userIdFromSession}`,
                userId: userIdFromSession
            });
        }

        const userData = results[0];

        res.render("main-logged-page.ejs", { 
            userId: userIdFromSession, 
            requestedId: userIdFromUrl,
            userData: userData
        });
    });
});

app.post('/register', async (req, res) => {
    const { user, password, name, surname } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const sql = `
            INSERT INTO users_secure (user, password, name, surname, role)
            VALUES (?, ?, ?, ?, 'user')
        `;
        
        db.query(sql, [user, hashedPassword, name, surname], (err, result) => {
            if (err) {
                console.error('Błąd zapisu rejestracji:', err);
                return res.send('Błąd rejestracji.');
            }
            res.redirect("/");
        });

    } catch (error) {
        console.error('Błąd hashowania:', error);
        res.status(500).send('Błąd serwera podczas hashowania hasła.');
    }
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect(`/main-logged-page/${req.session.userId}`);
    }
    res.render('login.ejs');
});

app.get('/login-secure', (req, res) => {
    if (req.session.userId) {
        return res.redirect(`/main-logged-page-secure/${req.session.userId}`);
    }
    res.render('login-secure.ejs');
});

app.post('/login', async (req, res) => {
    const { user, password } = req.body;

    const sql = 'SELECT id, user, password FROM users_secure WHERE user = ?';
    
    db.query(sql, [user], async (err, results) => {
        console.log(results)
        if (err || results.length === 0) {
            return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }

        const dbUser = results[0];
        
        const match = await bcrypt.compare(password, dbUser.password);

        if (match) {
            req.session.userId = dbUser.id;
            console.log(`Użytkownik ${dbUser.user} zalogowany pomyślnie.`);
            return res.redirect(`/main-logged-page/${req.session.userId}`);
        } else {
            return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }
    });
});

app.post('/login-secure', async (req, res) => {
    const { user, password } = req.body;

    const sql = 'SELECT id, user, password FROM users_secure WHERE user = ?';
    
    db.query(sql, [user], async (err, results) => {
        console.log(results)
        if (err || results.length === 0) {
            return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }

        const dbUser = results[0];
        
        const match = await bcrypt.compare(password, dbUser.password);

        if (match) {
            req.session.userId = dbUser.id;
            console.log(`Użytkownik ${dbUser.user} zalogowany pomyślnie.`);
            return res.redirect(`/main-logged-page-secure/${req.session.userId}`);
        } else {
            return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
        }
    });
});

app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                console.error('Błąd wylogowania:', err);
                return res.status(500).send('Błąd wylogowania.');
            }
            res.redirect('/login');
        });
    } else {
        res.redirect('/login');
    }
});

app.listen(port, () => {
    console.log(`🚀 Serwer działa na http://localhost:${port}`);
    // Musisz zrestartować serwer, a następnie zarejestrować użytkowników przez trasę /register.
    console.log(`Podatne A01: http://localhost:${port}/vulnerable/a01?id=1`);
});