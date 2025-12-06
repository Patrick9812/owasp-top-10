const express = require('express');
const bcrypt = require('bcrypt');
const axios = require('axios');
const SWAPI_PEOPLE_URL = 'https://swapi.dev/api/people/';

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
                res.redirect("/login");
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

        const sql = 'SELECT id, user, name, surname, role FROM users_unsecure WHERE id = ?';

        dbUnsecure.query(sql, [requestedId], (err, results) => {
            if (err || results.length === 0) {
                
            }

            const userData = results[0];

            res.render("main-logged-page.ejs", { 
                userId: loggedInId, 
                requestedId: requestedId,
                userData: userData
            });
        });
    });

    router.get('/star-wars/random-character/:id', async (req, res) => {
        const requestedId = req.params.id; 
        const loggedInId = req.session.userId;
        let characterData

        try {
            const initialResponse = await axios.get(SWAPI_PEOPLE_URL);
            const totalCharacters = initialResponse.data.count;
            
            if (totalCharacters === 0) {
                return res.status(503).json({ message: 'Brak postaci w SWAPI.' });
            }

            const randomId = Math.floor(Math.random() * totalCharacters) + 1;
            const characterResponse = await axios.get(`${SWAPI_PEOPLE_URL}${randomId}/`);

            characterData = ({
                random_id: randomId,
                character: characterResponse.data
            });

        } catch (error) {
            if (error.response && error.response.status === 404) {
                 return res.status(503).json({ 
                     message: 'Wylosowano pusty slot danych (404). Spróbuj ponownie.',
                     hint: 'Ponieważ SWAPI ma luki w indeksowaniu, wylosowano ID, pod którym brakuje danych.'
                 });
            }
            
            console.error('Błąd podczas losowania postaci:', error.message);
            return res.status(500).json({ 
                status: 'Błąd serwera', 
                message: 'Problem z połączeniem z SWAPI.' 
            });
        }
        res.render("star-wars-character.ejs", {characterData, userId: loggedInId,})
    });

    router.get('/change-password', (req, res) => {
        const userId = req.session.userId

        res.render('change-password.ejs', { userId });
    });

    router.post('/change-password', async (req, res) => {
        const loggedInId = req.session.userId;
        const { current_password, new_password } = req.body;
        
        if (!loggedInId) {
            return res.redirect('/login');
        }

        const selectSql = 'SELECT password FROM users_unsecure WHERE id = ?';
        
        dbUnsecure.query(selectSql, [loggedInId], (err, results) => {
            if (err || results.length === 0) {
                console.error('Błąd odczytu hasła do weryfikacji:', err);
                return res.render('change-password.ejs', { 
                    userId: loggedInId, 
                    error: 'Wystąpił błąd serwera. Spróbuj ponownie.', 
                });
            }

            const dbPassword = results[0].password; 

            if (current_password != dbPassword) {
                return res.render('change-password.ejs', { 
                    userId: loggedInId, 
                    error: 'Nieprawidłowe aktualne hasło.', 
                });
            }

            const updateSql = `
                UPDATE users_unsecure 
                SET password = '${new_password}' 
                WHERE id = ${loggedInId}
            `;
            
            dbUnsecure.query(updateSql, (err, result) => {
                if (err) {
                    console.error('Błąd aktualizacji hasła:', err);
                    return res.render('change-password.ejs', { 
                        userId: loggedInId, 
                        error: 'Błąd aktualizacji hasła.', 
                    });
                }

                res.render('change-password.ejs', { 
                    userId: loggedInId, 
                    error: null, 
                    success: 'Hasło zostało pomyślnie zmienione (niezabezpieczone!).' 
                });
            });
        });
    });

    return router;
};