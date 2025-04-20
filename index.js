const express = require('express');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB and Server Setup
const dbPath = path.join(__dirname, 'agrofix.db');
let db = null;

// Initialize the database connection
const initializeDBAndServer = async () => {
  try {
    db = await open({ filename: dbPath, driver: sqlite3.Database });

    // Create tables if they don't exist
    await db.exec(`
      CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        name TEXT,
        password TEXT,
        gender TEXT,
        location TEXT
      );

      CREATE TABLE IF NOT EXISTS product (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price INTEGER,
        quantity INTEGER
      );

      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        FOREIGN KEY (user_id) REFERENCES user(id),
        FOREIGN KEY (product_id) REFERENCES product(id)
      );
    `);

    // Add some sample products to the product table for real-time experience
    const sampleProducts = [
      ['Apple', 30, 100],
      ['Banana', 15, 150],
      ['Carrot', 20, 120],
      ['Tomato', 25, 80],
      ['Cucumber', 18, 90],
    ];

    for (const product of sampleProducts) {
      await db.run(
        `INSERT OR IGNORE INTO product (name, price, quantity) VALUES (?, ?, ?)`,
        product
      );
    }

    app.listen(process.env.PORT || 3000, () =>
      console.log(`🚀 Server running at http://localhost:${process.env.PORT || 3000}`)
    );
  } catch (e) {
    console.error(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
initializeDBAndServer();

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).send('Missing Token');

  jwt.verify(token, process.env.JWT_SECRET || 'MY_SECRET_TOKEN', (err, user) => {
    if (err) return res.status(403).send('Invalid Token');
    req.user = user;
    next();
  });
};

// Health Check
app.get('/', (req, res) => {
  res.send('🌿 Agrofix API is up and running!');
});

// User Register
app.post('/users/', async (req, res) => {
  const { username, name, password, gender, location } = req.body;
  if (!username || !name || !password || !gender || !location) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const userExists = await db.get(`SELECT * FROM user WHERE username = ?`, [username]);

  if (userExists) {
    return res.status(400).json({ error: 'User already exists' });
  }

  await db.run(
    `INSERT INTO user (username, name, password, gender, location) VALUES (?, ?, ?, ?, ?)`,
    [username, name, hashedPassword, gender, location]
  );
  res.status(201).json({ message: 'User registered successfully' });
});

// User Login
app.post('/login/', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get(`SELECT * FROM user WHERE username = ?`, [username]);

  if (!user) return res.status(400).json({ error: 'Invalid User' });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: 'Invalid Password' });

  const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'MY_SECRET_TOKEN');
  res.json({ jwtToken: token });
});

// Get All Products (Public)
app.get('/products/', async (req, res) => {
  const products = await db.all(`SELECT * FROM product`);
  res.json(products);
});

// Add Product (Protected)
app.post('/products/', authenticateToken, async (req, res) => {
  const { name, price, quantity } = req.body;
  if (!name || !price || !quantity) return res.status(400).send('Missing fields');

  await db.run(`INSERT INTO product (name, price, quantity) VALUES (?, ?, ?)`, [
    name,
    price,
    quantity,
  ]);
  res.status(201).send('Product added successfully');
});

// Place Order (Protected)
app.post('/orders/', authenticateToken, async (req, res) => {
  const { product_id, quantity } = req.body;
  const user_id = req.user.userId;

  const product = await db.get(`SELECT * FROM product WHERE id = ?`, [product_id]);
  if (!product) return res.status(400).send('Product not found');
  if (product.quantity < quantity) return res.status(400).send('Insufficient stock');

  await db.run(
    `INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)`,
    [user_id, product_id, quantity]
  );

  await db.run(
    `UPDATE product SET quantity = quantity - ? WHERE id = ?`,
    [quantity, product_id]
  );

  res.status(201).send('Order placed successfully');
});

// View Orders (Protected)
app.get('/orders/', authenticateToken, async (req, res) => {
  const orders = await db.all(
    `SELECT o.id, p.name as product, o.quantity
     FROM orders o
     JOIN product p ON o.product_id = p.id
     WHERE o.user_id = ?`,
    [req.user.userId]
  );
  res.json(orders);
});
