require('dotenv').config();
const express = require("express");
const jwt = require ('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const users = [];
const mockData = [
    { userName: 'User1', data: 'unique auth data 1' },
    { userName: 'User2', data: 'unique auth data 2' }
];


app.get("/", (req, res) => {
    res.status(200).send(users)
});

//Get data for authenticaded users only
app.get("/getMockData", authenticateToken, (req, res) => {
    res.json(mockData.filter(el => el.userName === req.user.name));
});

//Register a new user to the database
app.post("/users/register", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { name: req.body.name, password: hashedPassword };
        users.push(user);
        res.status(201).send(users);
    } catch {
        res.status(500).send();
    }
});

//Login and generate jwt token for authentication
app.post("/users/login", async (req, res) => {
    const user = users.find((user) => user.name === req.body.name);

    if (!user) {
        return res.status(400).send("Cannot find user");
    }

    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const username = req.body.username
            const user = { name: username }
          
            const accessToken = generateAccessToken(user)
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
            refreshTokens.push(refreshToken)
            res.json({ accessToken: accessToken, refreshToken: refreshToken })
        } else {
            res.send("Not Allowed");
        }
    } catch {
        res.status(500).send();
    }
});

let refreshTokens = []

app.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ name: user.name })
    res.json({ accessToken: accessToken })
  })
})

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
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

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
};

app.listen(3000, () => {
    console.log('Server running on port 3000');
});