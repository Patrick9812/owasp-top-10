const express = require('express');
const bcrypt = require('bcrypt'); 

module.exports = ({ dbUnsecure }) => {
    const router = express.Router();
    
    router.get('/register', (req, res) => {
        const userId = req.session.userId; 
        res.render("register.ejs", { userId: userId });
    });

    router.post('/register', async (req, res) => {
        const { user, password, name, surname } = req.body;
        
        try {
            const sql = `
                INSERT INTO users_unsecure (user, password, name, surname, role)
                VALUES ('${user}', '${password}', '${name}', '${surname}', 'user')
            `;

            // Kod podatny na sql injection. Wpisać w nazwisku: Kowalski', 'user'); DROP TABLE users_unsecure; #
            dbUnsecure.query(sql, (err, result) => {
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

    router.get('/login', (req, res) => {
        if (req.session.userId) {
            return res.redirect(`/main-logged-page/${req.session.userId}`);
        }
        res.render('login.ejs');
    });

    router.post('/login', async (req, res) => {
        const { user, password } = req.body;

        const sql = 'SELECT id, user, password FROM users_unsecure WHERE user = ?';
        
        dbUnsecure.query(sql, [user], async (err, results) => {
            console.log(results)
            if (err || results.length === 0) {
                return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
            }

            const dbUser = results[0];

            if (password == dbUser.password) {
                req.session.userId = dbUser.id;
                console.log(`Użytkownik ${dbUser.user} zalogowany pomyślnie.`);
                return res.redirect(`/main-logged-page/${req.session.userId}`);
            } else {
                return res.render('login.ejs', { error: 'Nieprawidłowa nazwa użytkownika lub hasło.' });
            }
        });
    });

    router.get('/main-logged-page/:id', (req, res) => {
        const requestedId = req.params.id; 
        const loggedInId = req.session.userId;

        if (!loggedInId) {
            return res.redirect('/login');
        }

        const sql = 'SELECT id, user, name, surname, role FROM users_unsecure WHERE id = ?';

        dbUnsecure.query(sql, [requestedId], (err, results) => {
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

    return router;
};