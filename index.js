const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize DB
const dbPath = path.join(__dirname, 'agrofix.db');
const db = new Database(dbPath);

// Create tables if not exists
db.exec(`
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

// Insert sample products
const sampleProducts = [
  ['Apple', 30, 100],
  ['Banana', 15, 150],
  ['Carrot', 20, 120],
  ['Tomato', 25, 80],
  ['Cucumber', 18, 90],
];

const insertStmt = db.prepare(
  `INSERT OR IGNORE INTO product (name, price, quantity) VALUES (?, ?, ?)`
);
sampleProducts.forEach((product) => insertStmt.run(...product));

// Start server
app.listen(process.env.PORT || 3000, () =>
  console.log(`🚀 Server running at http://localhost:${process.env.PORT || 3000}`)
);

// Middleware for JWT auth
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

// Register
app.post('/users/', (req, res) => {
  const { username, name, password, gender, location } = req.body;
  if (!username || !name || !password || !gender || !location) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const userExists = db
    .prepare(`SELECT * FROM user WHERE username = ?`)
    .get(username);
  if (userExists) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  db.prepare(
    `INSERT INTO user (username, name, password, gender, location) VALUES (?, ?, ?, ?, ?)`
  ).run(username, name, hashedPassword, gender, location);

  res.status(201).json({ message: 'User registered successfully' });
});

// Login
app.post('/login/', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare(`SELECT * FROM user WHERE username = ?`).get(username);

  if (!user) return res.status(400).json({ error: 'Invalid User' });

  const isValid = bcrypt.compareSync(password, user.password);
  if (!isValid) return res.status(400).json({ error: 'Invalid Password' });

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    process.env.JWT_SECRET || 'MY_SECRET_TOKEN'
  );
  res.json({ jwtToken: token });
});

// Get All Products
app.get('/products/', (req, res) => {
  const products = db.prepare(`SELECT * FROM product`).all();
  res.json(products);
});

// Add Product
app.post('/products/', authenticateToken, (req, res) => {
  const { name, price, quantity } = req.body;
  if (!name || !price || !quantity) return res.status(400).send('Missing fields');

  db.prepare(`INSERT INTO product (name, price, quantity) VALUES (?, ?, ?)`).run(
    name,
    price,
    quantity
  );

  res.status(201).send('Product added successfully');
});

// Place Order
app.post('/orders/', authenticateToken, (req, res) => {
  const { product_id, quantity } = req.body;
  const user_id = req.user.userId;

  const product = db.prepare(`SELECT * FROM product WHERE id = ?`).get(product_id);
  if (!product) return res.status(400).send('Product not found');
  if (product.quantity < quantity)
    return res.status(400).send('Insufficient stock');

  db.prepare(
    `INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)`
  ).run(user_id, product_id, quantity);

  db.prepare(`UPDATE product SET quantity = quantity - ? WHERE id = ?`).run(
    quantity,
    product_id
  );

  res.status(201).send('Order placed successfully');
});

// View Orders
app.get('/orders/', authenticateToken, (req, res) => {
  const user_id = req.user.userId;
  const orders = db
    .prepare(
      `SELECT o.id, p.name as product, o.quantity
       FROM orders o
       JOIN product p ON o.product_id = p.id
       WHERE o.user_id = ?`
    )
    .all(user_id);

  res.json(orders);
});
