# MyProject
SecurityBoat Assessment Test: code

Backend (Node.js + Express.js + MongoDB)
app.js - Entry point for Express server
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
const dbURI = 'your_mongodb_uri_here';
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch((err) => console.log(err));

// Routes
const userRoutes = require('./routes/userRoutes');
const movieRoutes = require('./routes/movieRoutes');
const bookingRoutes = require('./routes/bookingRoutes');

app.use('/api/users', userRoutes);
app.use('/api/movies', movieRoutes);
app.use('/api/bookings', bookingRoutes);


// Serve static assets 
if (process.env.NODE_ENV === 'production') {
  app.use(express.static('client/build'));
  
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
  });
}
models/User.js - User schema and model

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function (next) {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});
const User = mongoose.model('User', userSchema);

module.exports = User;

routes/userRoutes.js - User authentication routes
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// User registration
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ name, email, password });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, 'your_jwt_secret_here');
    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Registration failed' });
  }
});

// User login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret_here');
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Login failed' });
  }
});

module.exports = router;

models/Movie.js - Movie schema and model
const mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
  title: { type: String, required: true },
  genre: { type: String, required: true },
  showtimes: { type: [String], required: true },
  seats: {
    type: [{
      row: { type: Number, required: true },
      number: { type: Number, required: true },
      available: { type: Boolean, default: true }
    }],
    required: true
  }
});

const Movie = mongoose.model('Movie', movieSchema);

module.exports = Movie;

routes/movieRoutes.js - Movie CRUD routes
const express = require('express');
const router = express.Router();
const Movie = require('../models/Movie');

// Fetch all movies
router.get('/', async (req, res) => {
  try {
    const movies = await Movie.find();
    res.json(movies);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch movies' });
  }
});

// Add a new movie
router.post('/', async (req, res) => {
  try {
    const newMovie = new Movie(req.body);
    await newMovie.save();
    res.status(201).json({ message: 'Movie added successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to add movie' });
  }
});

// Update movie details
router.patch('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updatedMovie = await Movie.findByIdAndUpdate(id, req.body, { new: true });
    res.json(updatedMovie);
  } catch (error) {
    res.status(500).json({ message: 'Failed to update movie details' });
  }
});

// Delete a movie
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await Movie.findByIdAndDelete(id);
    res.json({ message: 'Movie deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete movie' });
  }
});

module.exports = router;
models/Booking.js - Booking schema and model
const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  movieId: { type: mongoose.Schema.Types.ObjectId, ref: 'Movie', required: true },
  seats: { type: [String], required: true },
  totalTickets: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Booking = mongoose.model('Booking', bookingSchema);

module.exports = Booking;
routes/bookingRoutes.js - Booking routes
const express = require('express');
const router = express.Router();
const Booking = require('../models/Booking');
const { authenticateUser } = require('../utils/auth');

// Made a booking
router.post('/', authenticateUser, async (req, res) => {
  try {
    const { userId, movieId, seats, totalTickets, totalPrice } = req.body;
    const newBooking = new Booking({ userId, movieId, seats, totalTickets, totalPrice });
    await newBooking.save();
    res.status(201).json({ message: 'Booking successful' });
  } catch (error) {
    res.status(500).json({ message: 'Booking failed' });
  }
});

// Fetch user bookings
router.get('/user/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const bookings = await Booking.find({ userId }).populate('movieId', 'title genre showtimes');
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch bookings' });
  }
});

module.exports = router;
Frontend (React.js)
App.js - Main component with routing
import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import BookingPage from './pages/BookingPage';
import AdminPage from './pages/AdminPage';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Switch>
          <Route exact path="/" component={HomePage} />
          <Route path="/login" component={LoginPage} />
          <Route path="/register" component={RegisterPage} />
          <Route path="/booking" component={BookingPage} />
          <Route path="/admin" component={AdminPage} />
        </Switch>
      </div>
    </Router>
  );
}

export default App;





LoginPage.js - Login form component
import React, { useState } from 'react';
import { loginUser } from '../utils/api';

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await loginUser({ email, password });
      localStorage.setItem('token', response.data.token);
      // Redirect to booking page or homepage
    } catch (error) {
      setError('Invalid credentials');
    }
  };

  return (
    <div className="login-page">
      <form onSubmit={handleLogin}>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" required />
        <button type="submit">Login</button>
      </form>
      {error && <p className="error-message">{error}</p>}
    </div>
  );
};

export default LoginPage;
RegisterPage.js - Registration form component
import React, { useState } from 'react';
import { registerUser } from '../utils/api';

const RegisterPage = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await registerUser({ name, email, password });
      // Redirect to login page
    } catch (error) {
      setError('Registration failed');
    }
  };

  return (
    <div className="register-page">
      <form onSubmit={handleRegister}>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" required />
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" required />
        <button type="submit">Register</button>
      </form>
      {error && <p className="error-message">{error}</p>}
    </div>
  );
};

export default RegisterPage;
``
