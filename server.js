require('dotenv').config();
const express = require("express");
const jwt = require ('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db/database');

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
    res.status(200).send(users)
});

app.get("/getData", authenticateToken, async (req, res) => {
    
    try{
        const data = await db.query('SELECT * FROM Contacts');
    }catch (e) {
        res.status(500).send(e)
    }
    res.status(201).send(data);
});

app.post("/users/register", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.PASSWORD, 10);
        const user = { USER_NAME: req.body.USER_NAME, PASSWORD: hashedPassword };
        const sInsert = 'INSERT INTO USERS (USER_NAME, PASSWORD) VALUES (?, ?)';
        const result = await db.execute(sInsert, [user.USER_NAME, user.PASSWORD]);
        res.status(201).send(result);
    } catch (e) {
        res.status(500).send(e);
    }
});

app.post("/users/login", async (req, res) => {
    
    const { USER_NAME, PASSWORD } = req.body;
    const sSelect = 'SELECT * FROM USERS WHERE USER_NAME = ?';
    const rows = await db.execute(sSelect, [USER_NAME]);
    const dbUser = rows[0];

    if (!dbUser) {
        return res.status(400).send("Cannot find user");
    }

    try {
        if (await bcrypt.compare(req.body.PASSWORD, dbUser[0].PASSWORD)) {
            const username = req.body.USER_NAME
            const jwtUser = { name: username }
            const accessToken = generateAccessToken(jwtUser)
            const refreshToken = jwt.sign(jwtUser, process.env.REFRESH_TOKEN_SECRET)
            const sInsert = 'INSERT INTO AUTH (REFRESH_TOKEN) VALUES (?)';
            await db.query(sInsert, [refreshToken]);
            res.json({ accessToken: accessToken, refreshToken: refreshToken })
        } else {
            res.send("Password non corretta");
        }
    } catch(e) {
        res.status(500).send(e);
    }
});

app.post('users/refresh', async(req, res) => {

  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)

    try{
        const sSelect = 'SELECT * FROM AUTH WHERE REFRESH_TOKEN = ?';
        const rows = await db.query(sSelect, [refreshToken]);
        if (rows.length === 0) {
            return res.sendStatus(403);
        }
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, jwtUser) => {
          if (err) return res.sendStatus(403)
          const accessToken = generateAccessToken({ name: jwtUser.name })
          res.json({ accessToken: accessToken })
        })
    }catch(e){

    }
    
})

app.delete('/users/logout', async (req, res) => {
    const tokenToDelete = req.body.token;
    const sDelete = 'DELETE FROM AUTH WHERE REFRESH_TOKEN = ?';

    try{
        const test = await db.execute(sDelete, [tokenToDelete])
        console.log('Token di refresh eliminato con successo dal database');
        res.status(204).send(test); 
    }catch(e){
        res.status(500).send(e)
    }
})


//Verify jwt token of logged user
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send(authHeader);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

function generateAccessToken(jwtUser) {
    return jwt.sign(jwtUser, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '59s' })
};

app.listen(3000, () => {
    console.log('Server running on port 3000');
});