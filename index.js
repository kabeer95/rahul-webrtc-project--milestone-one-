const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const serviceAccount = require('./path-to-your-service-account-file.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY;

// Signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  const usersRef = db.collection('users');
  const userSnapshot = await usersRef.where('email', '==', email).get();
  if (!userSnapshot.empty) {
    return res.status(400).send('Email already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await usersRef.add({ email, password: hashedPassword });

  res.status(201).send('User created');
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  const usersRef = db.collection('users');
  const userSnapshot = await usersRef.where('email', '==', email).get();
  if (userSnapshot.empty) {
    return res.status(400).send('Invalid email or password');
  }

  const user = userSnapshot.docs[0].data();
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send('Invalid email or password');
  }

  const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.status(200).json({ token });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
