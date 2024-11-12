const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// Middleware
const allowedOrigins = [process.env.ALLOWED_ORIGIN || 'https://testuser057.github.io'];
app.use(cors({ origin: allowedOrigins }));
app.use(express.json());

// MongoDB connection setup
const dbURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/guardian-optix-db';
mongoose.connect(dbURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

})
  .then(() => console.log('MongoDB Connected...'))
  .catch((error) => console.error('MongoDB Connection Error:', error));

// Import and use routes
const authRoutes = require('./routes/authRoutes');
const taskRoutes = require('./routes/taskRoutes');
const scheduleRoutes = require('./routes/scheduleRoutes');
app.use('/api', authRoutes);
app.use('/api', taskRoutes);
app.use('/api', scheduleRoutes);

// Server setup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

});
