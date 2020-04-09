require('dotenv').config();
const express = require('express');
const app = express();
const massive = require('massive');
const bcrypt = require('bcryptjs');
const session = require('express-session');

app.use(express.json());

const {SERVER_PORT, SESSION_SECRET, DATABASE_STRING} = process.env;

massive(DATABASE_STRING)
    .then(db => {
        app.set('db', db);
        console.log('DB connected')
    })
    .catch(err => console.log(err));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

// register and login endpoints
// typically the handler functions would be in their own authController file
// presented this way for simplicity
app.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    const db = req.app.get('db');

    db.auth.checkForUsername(username).then(users => {
        if (users.length > 0) {
            res.status(409).json({ error: 'Username Taken'})
        } else {
            bcrypt.genSalt().then(salt => {

                bcrypt.hash(password, salt).then(hash => {
                   db.auth.addUser(username, hash).then(() => {

                    req.session.user = {
                        username
                    }

                    res.status(200).json(req.session.user)
                   })
                })
            })
        }
    })
});

app.post('/auth/login', async (req, res) => {
    const {username, password} = req.body;
    const db = req.app.get('db');

    const hash = await db.auth.getHash(username);
    const userHash = hash[0].hash;

    const doesMatch = await bcrypt.compare(password, userHash);

    if (!doesMatch) {
        res.status(403).json({ error: 'Incorrect username or password'})
    } else {
        req.session.user = {
            username
        }

        res.status(200).json(req.session.user)
    }
});

app.listen( SERVER_PORT, () => console.log(`Server listening on ${SERVER_PORT}`) )