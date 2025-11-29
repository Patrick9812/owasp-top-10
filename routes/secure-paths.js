const express = require('express');
const bcrypt = require('bcrypt'); 
const { loginSchema } = require('../schemas/loginSchema.js');
const { requireLogin } = require('../middleware/requireLogin.js');
const { encrypt, decrypt } = require('../utils/encryption.js');
const nodeFetch = require('node-fetch');
const { registerSchema } = require('../schemas/registerSchema.js');
const { changePasswordSchema } = require('../schemas/changePasswordSchema.js');
const fetch = nodeFetch.default || nodeFetch;

module.exports = ({ db, loginLimiter, saltRounds, fetch, safeFetchResource }) => {
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
            const checkUserSql = 'SELECT id FROM users_secure WHERE user = ?';

            const existingUser = await new Promise((resolve, reject) => {
                db.query(checkUserSql, [user], (err, results) => {
                    if (err) return reject(err);
                    resolve(results);
                });
            });
            
            if (existingUser.length > 0) {
                console.warn(`[A07] Próba rejestracji istniejącego użytkownika: ${user}. IP: ${clientIp}`);
                return res.render('register-secure.ejs', { 
                    error: 'Podana nazwa użytkownika jest już zajęta.', 
                    publicKey: publicKey
                });
            }

            const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}&remoteip=${clientIp}`;
            

            // A10 Server-Side Request Forgery (SSRF)
            const verificationBuffer = await safeFetchResource(verificationUrl, fetch);
            const data = JSON.parse(verificationBuffer.toString());

            if (!data.success || data.score < MINIMUM_SCORE) {
                console.warn(`[A07] Bot/niski wynik reCAPTCHA (${data.score}) dla rejestracji użytkownika: ${user}. IP: ${clientIp}`);
                return res.render('register-secure.ejs', { error: 'Weryfikacja bota nieudana. Spróbuj ponownie.', publicKey });
            }
            
            console.info(`[A07] Rejestracja CAPTCHA V3 udana. Wynik: ${data.score}.`);
        // A10 Server-Side Request Forgery (SSRF)
        } catch (e) {
            if (e.message && e.message.includes('[A10:2021 SSRF]')) {
                console.error(`[A10:2021 SSRF BLOCKED] Użycie zablokowanej domeny/IP: ${e.message}`);
                return res.status(403).render('register-secure.ejs', { error: 'Błąd zabezpieczeń (próba dostępu do nieautoryzowanego zasobu).', publicKey });
            }
            console.error(`[A09] Błąd komunikacji z CAPTCHA API: ${e.message}`);
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
        const publicKey = process.env.PUBLIC_RECAPTCHA_KEY;
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
            // A10 Server-Side Request Forgery (SSRF)
            const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captchaResponse}&remoteip=${clientIp}`;
            // Weryfikacja whitelisty adresów IP - symulacja (ochrona przed SSRF)
            // const verificationUrl = `http://127.0.0.1`;
            const verificationBuffer = await safeFetchResource(verificationUrl, fetch);
            const data = JSON.parse(verificationBuffer.toString());

            if (!data.success || data.score < MINIMUM_SCORE) {
                console.warn(`[A07] Bot/niski wynik (${data.score}) dla ${user}. IP: ${clientIp}`);
                return res.render('login-secure.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.', publicKey: process.env.PUBLIC_RECAPTCHA_KEY });
            }
            
            console.info(`[A07] CAPTCHA V3 udana. Wynik: ${data.score}.`);

        // A10 Server-Side Request Forgery (SSRF)
        } catch (e) {
            if (e.message && e.message.includes('[A10:2021 SSRF]')) {
                console.error(`[A10:2021 SSRF BLOCKED] Użycie zablokowanej domeny/IP: ${e.message}`);
                return res.status(403).render('register-secure.ejs', { error: 'Błąd zabezpieczeń (próba dostępu do nieautoryzowanego zasobu).', publicKey });
            }
            console.error(`[A09] Błąd komunikacji z CAPTCHA API: ${e.message}`);
            return res.status(500).render('register-secure.ejs', { error: 'Błąd serwera.', publicKey });
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

    router.get('/change-password-secure', (req, res) => {
            const loggedInId = req.session.userId;
            console.log(loggedInId)
            if (!loggedInId) {
                return res.redirect('/login-secure');
            }
            res.render('change-password-secure.ejs', { userId: loggedInId });
        });
    
    router.post('/change-password-secure', async (req, res) => {
        const loggedInId = req.session.userId;
        const clientIp = req.ip; 
        const { currentPassword, newPassword, repeatNewPassword } = req.body;

        if (!loggedInId) {
            return res.redirect('/login-secure');
        }

        const { error } = changePasswordSchema.validate(req.body);

        if (error) {
            const errorMessage = error.details[0].message;
            console.warn(`[A09/A07] Walidacja Joi nieudana dla IP: ${clientIp}. Błąd: ${errorMessage}`);
            
            return res.render("change-password-secure.ejs", { 
                error: errorMessage, 
                publicKey: process.env.PUBLIC_RECAPTCHA_KEY
            });
        }
    
        const selectSql = 'SELECT password FROM users_secure WHERE id = ?';
            
        db.query(selectSql, [loggedInId], async (err, results) => {
            if (err || results.length === 0) {
                console.error('Błąd odczytu hasła do weryfikacji:', err);
                return res.render('change-password-secure.ejs', { 
                    userId: loggedInId, 
                    error: 'Wystąpił błąd serwera. Spróbuj ponownie.', 
                    success: null 
                });
            }
    
            const dbPasswordHash = results[0].password;
    
            try {
                const isMatch = await bcrypt.compare(currentPassword, dbPasswordHash);
    
                if (!isMatch) {
                    return res.render('change-password-secure.ejs', { 
                        userId: loggedInId, 
                        error: 'Nieprawidłowe aktualne hasło.', 
                        success: null 
                    });
                }
            } catch (bcryptError) {
                console.error('Błąd podczas porównywania haseł (bcrypt):', bcryptError);
                return res.render('change-password-secure.ejs', { 
                    userId: loggedInId, 
                    error: 'Błąd weryfikacji hasła.', 
                    success: null 
                });
            }
                
            let newPasswordHash;
            try {
                const saltRounds = 10;
                newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
            } catch (hashError) {
                console.error('Błąd hashowania nowego hasła:', hashError);
                return res.render('change-password-secure.ejs', { 
                    userId: loggedInId, 
                    error: 'Błąd serwera podczas hashowania hasła.', 
                    success: null 
                });
            }

            const updateSql = 'UPDATE users_secure SET password = ? WHERE id = ?';
            const params = [newPasswordHash, loggedInId];
    
            db.query(updateSql, params, (updateErr, result) => {
                if (updateErr) {
                    console.error('Błąd bezpiecznej aktualizacji hasła:', updateErr);
                    return res.render('login-secure.ejs', { 
                        userId: loggedInId, 
                        error: 'Błąd aktualizacji hasła.', 
                        success: null 
                    });
                }

                req.session.destroy(err => {
                    if (err) {
                        console.error('Błąd wylogowania sesji:', err);
                    }

                    return res.redirect('/login-secure?success=Hasło_zostało_pomyślnie_zmienione._Zaloguj_się_ponownie.');
                });
            });
        });
    });

    return router;
};