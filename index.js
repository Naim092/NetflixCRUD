const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");

const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    port: 3307, 
    database: "netflixdb",
});

const app = express();
app.use(bodyParser.json());

const generateToken = (userId) => {
    const token = jwt.sign({ userId }, 'your-secret-key', { expiresIn: '1h' });
    return token;
};

const getUsers = async (req, res, next) => {
    // ... (unchanged)
};

const createUser = async (req, res, next) => {
    const { email, phone_no, password, is_active } = req.body;

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    const queryString = `
      INSERT INTO users 
      (email, phone_no, passward, is_active)
      VALUES (?, ?, ?, ?);
    `;

    const [results] = await connection
        .promise()
        .execute(queryString, [email, phone_no, hashedPassword, is_active]);

    res.status(201).send({
        message: "User added successfully",
        results,
    });
};

const getUserDetails = async (req, res, next) => {
    try {
        // ... (unchanged)
    } catch (err) {
        res.status(500).send({ message: "Internal Server Error" });
    }
};

const comparePasswords = async (plainPassword, hashedPassword) => {
    return await bcrypt.compare(plainPassword, hashedPassword);
};

// Login API with JWT authentication
app.post("/login", async (req, res) => {
    const { phone_no, password } = req.body;

    const queryString = "SELECT id, passward FROM users WHERE phone_no = ?";
    const [results] = await connection.promise().execute(queryString, [phone_no]);

    if (results.length === 0) {
        res.status(401).send({ message: "Invalid credentials" });
        return;
    }

    const user = results[0];
    const isValidPassword = await comparePasswords(password, user.passward);

    if (isValidPassword) {
        // Generate JWT token upon successful login
        const token = generateToken(user.id);

        res.status(200).send({ message: "Login successful", userId: user.id, token });
    } else {
        res.status(401).send({ message: "Invalid credentials" });
    }
});

// Protected route with JWT authentication
app.get("/users/:id", authenticateToken, getUserDetails);

// Users API
app.get("/users", getUsers);
app.post("/users", createUser);

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');

    if (!token) return res.status(401).send({ message: 'Access denied' });

    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) return res.status(403).send({ message: 'Invalid token' });

        req.userId = decoded.userId;
        next();
    });
}

app.listen(3001, () => console.log("Server started"));


