const express = require('express');
const cors = require('cors');
//const babyRoutes = require('./routes/babyRoutes');
const authRoutes = require('./routes/authRoutes');

// Initialize Express app
const app = express();

// Middleware
//app.use(cors());
app.use(cors({
  origin: "http://react-app-moviedb.s3-website.ap-south-1.amazonaws.com",   // Allow only Vite frontend
  methods: "GET,POST,PUT,DELETE",
  credentials: true                  // if using cookies
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
//app.use('/babies', babyRoutes);
app.use('/auth', authRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Movie DB API' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: err.message || 'Something went wrong',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Resource not found'
  });
});

module.exports = app;