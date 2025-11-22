const express = require('express');
const bcrypt = require('bcrypt'); 
const { loginSchema } = require('../schemas/loginSchema.js');
const { requireLogin } = require('../middleware/requireLogin.js');
const { encrypt, decrypt } = require('../utils/encryption.js');
const nodeFetch = require('node-fetch');
const { registerSchema } = require('../schemas/registerSchema.js');
const fetch = nodeFetch.default || nodeFetch;

module.exports = ({ db, loginLimiter, saltRounds, fetch }) => {
    const router = express.Router();

    router.get('/register-secure', (req, res) => {
        const userId = req.session.userId;
        const publicKey = process.env.PUBLIC_RECAPTCHA_KEY;
        res.render("register-secure.ejs", { userId, publicKey, error: undefined });
    });

    router.post('/register-secure', async (req, res) => {
        const { user, password, name, surname } = req.body;
        const clientIp = req.ip;

        const { error } = registerSchema.validate(req.body);

        if (error) {
            const errorMessage = error.details[0].message;
            console.warn(`[A09/A07] Walidacja Joi nieudana dla IP: ${clientIp}. Błąd: ${errorMessage}`);
            
            return res.render("register-secure.ejs", { 
                error: errorMessage, 
                publicKey: process.env.PUBLIC_RECAPTCHA_KEY
            });
        }

        const captchaResponse = req.body['g-recaptcha-response'];
        const secretKey = process.env.PRIVATE_RECAPTCHA_KEY;
        const publicKey = process.env.PUBLIC_RECAPTCHA_KEY;
        const MINIMUM_SCORE = 0.7;

        if (!captchaResponse) {
            return res.render('register-secure.ejs', { error: 'Wymagana weryfikacja CAPTCHA.', publicKey });
        }

        try {
            const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}&remoteip=${clientIp}`;
            
            const response = await fetch(verificationUrl, { method: 'POST' });
            const data = await response.json();

            if (!data.success || data.score < MINIMUM_SCORE) {
                console.warn(`[A07] Bot/niski wynik reCAPTCHA (${data.score}) dla rejestracji użytkownika: ${user}. IP: ${clientIp}`);
                return res.render('register-secure.ejs', { error: 'Weryfikacja bota nieudana. Spróbuj ponownie.', publicKey });
            }
            
            console.info(`[A07] Rejestracja CAPTCHA V3 udana. Wynik: ${data.score}.`);

        } catch (e) {
            console.error(`[A09] Błąd komunikacji z CAPTCHA API podczas rejestracji: ${e.message}`);
            return res.status(500).render('register-secure.ejs', { error: 'Błąd serwera.', publicKey });
        }
        
        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const encryptedName = encrypt(name);
            const encryptedSurname = encrypt(surname);

            console.log(name + "  " + encryptedName)
            
            const sql = `
                INSERT INTO users_secure (user, password, name, surname, role)
                VALUES (?, ?, ?, ?, 'user')
            `;
            
            db.query(sql, [user, hashedPassword, encryptedName, encryptedSurname], (err, result) => {
                if (err) {
                    console.error('Błąd zapisu rejestracji:', err);
                    return res.send('Błąd rejestracji.');
                }
                res.redirect("/login-secure");
            });

        } catch (error) {
            console.error('Błąd hashowania:', error);
            res.status(500).send('Błąd serwera podczas hashowania hasła.');
        }
    });

    router.get('/login-secure', (req, res) => {
        if (req.session.userId) {
            return res.redirect(`/main-logged-page-secure/${req.session.userId}`);
        }
        const publicKey = process.env.PUBLIC_RECAPTCHA_KEY;
        res.render('login-secure.ejs', {publicKey});
    });

    router.post('/login-secure', loginLimiter, async (req, res) => {
        const { user, password } = req.body;
        const clientIp = req.ip; 
        
        const { error } = loginSchema.validate(req.body);

        if (error) {
            const errorMessage = error.details[0].message;
            console.warn(`[A09/A07] Walidacja Joi nieudana dla IP: ${clientIp}. Błąd: ${errorMessage}`);
            
            return res.render("login-secure.ejs", { 
                error: errorMessage, 
                publicKey: process.env.PUBLIC_RECAPTCHA_KEY
            });
        }
        
        const captchaResponse = req.body['g-recaptcha-response'];
        const secretKey = process.env.PRIVATE_RECAPTCHA_KEY;
        const MINIMUM_SCORE = 0.7;

        if (!captchaResponse)
             return res.render('login-secure.ejs', { error: 'Błąd weryfikacji. Odśwież.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });

        try {
            const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}&remoteip=${clientIp}`;
            const response = await fetch(verificationUrl, { method: 'POST' });
            const data = await response.json();

            if (!data.success || data.score < MINIMUM_SCORE) {
                console.warn(`[A07] Bot/niski wynik (${data.score}) dla ${user}. IP: ${clientIp}`);
                return res.render('login-secure.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });
            }
            
            console.info(`[A07] CAPTCHA V3 udana. Wynik: ${data.score}.`);

        } catch (e) {
            console.error(`[A09] Błąd komunikacji z CAPTCHA API: ${e.message}`);
            return res.status(500).render('login-secure.ejs', { error: 'Błąd serwera.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });
        }

        const sql = 'SELECT id, user, password FROM users_secure WHERE user = ?';
        
        db.query(sql, [user], async (err, results) => {
            
            if (err || results.length === 0) {
                 console.warn(`[A09/A07] Nieudane logowanie: ${user}. IP: ${clientIp}`);
                 return res.render('login-secure.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });
            }

            const dbUser = results[0];
            const match = await bcrypt.compare(password, dbUser.password);

            if (match) {
                req.session.userId = dbUser.id;
                console.info(`[A09/A07] Użytkownik ${dbUser.user} zalogowany pomyślnie. IP: ${clientIp}`);
                return res.redirect(`/main-logged-page-secure/${req.session.userId}`);
            } else {
                 console.warn(`[A09/A07] Nieudane logowanie (błędne hasło) dla: ${user}. IP: ${clientIp}`);
                 return res.render('login-secure.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });
            }
        });
    });

    router.get('/main-logged-page-secure/:id', requireLogin, (req, res) => {
        const userIdFromSession = req.session.userId;
        const userIdFromUrl = parseInt(req.params.id); 

        if (userIdFromSession !== userIdFromUrl) {
            return res.status(403).send('Zabezpieczenie Broken Access Control');
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
            const decryptedName = decrypt(userData.name);
            const decryptedSurname = decrypt(userData.surname);

            res.render("main-logged-page-secure.ejs", { 
                userId: userIdFromSession, 
                requestedId: userIdFromUrl,
                userData,
                decryptedName,
                decryptedSurname
            });
        });
    });

    router.get('/logout', (req, res) => {
        if (req.session) {
            req.session.destroy(err => {
                if (err) {
                    console.error('Błąd wylogowania:', err);
                    return res.status(500).send('Błąd wylogowania.');
                }
                res.redirect('/login-secure');
            });
        } else {
            res.redirect('/login-secure');
        }
    });

    return router;
};