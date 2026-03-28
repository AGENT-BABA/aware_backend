const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const csv = require('csv-parser');
const path = require('path');

dotenv.config();

const mongodbUri = process.env.MONGODB_URI;
if (!mongodbUri || mongodbUri.includes('<db_password>')) {
  console.error('MongoDB URI is not configured correctly in .env. Replace <db_password> with your actual database password.');
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Log all requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// MongoDB User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, default: '' },
  password: { type: String, required: true },
  awsAccessKey: { type: String, default: '' },
  awsSecretKey: { type: String, default: '' },
});

const User = mongoose.model('User', userSchema);

// Connection to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Auth MiddleWare
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Auth Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, email = '' } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ message: 'SignUp failed', error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token, username: user.username, email: user.email, hasKeys: !!user.awsAccessKey });
  } catch (err) {
    res.status(500).json({ message: 'Login failed' });
  }
});

app.post('/api/aws-keys', authenticate, async (req, res) => {
  try {
    const { accessKey, secretKey } = req.body;
    await User.findByIdAndUpdate(req.userId, { awsAccessKey: accessKey, awsSecretKey: secretKey });
    res.json({ message: 'Keys updated' });
  } catch (err) {
    res.status(500).json({ message: 'Update failed' });
  }
});

// Cloud Data Processing
const readCSV = (filePath) => {
  return new Promise((resolve, reject) => {
    const results = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', () => resolve(results))
      .on('error', (err) => reject(err));
  });
};

app.get('/api/data', authenticate, async (req, res) => {
  try {
    const data = await readCSV(path.join(__dirname, process.env.CSV_PATH));
    // Data is large, send some sample (or last 100 rows for real-time feel)
    const recentData = data.slice(-200);
    res.json(recentData);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch data' });
  }
});

app.get('/api/anomalies', authenticate, async (req, res) => {
  try {
    const data = await readCSV(path.join(__dirname, process.env.CSV_PATH));
    const anomalies = data
      .map((d, i) => ({ ...d, index: i }))
      .filter(d => parseFloat(d.cpu_utilization) > 70 || parseFloat(d.error_rate) > 5)
      .slice(-5);
    res.json(anomalies);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch anomalies' });
  }
});

app.get('/api/actions', authenticate, async (req, res) => {
  try {
    const actions = [
      { timestamp: new Date().toISOString(), action: 'Auto-scaled EC2 Cluster', reason: 'High CPU utilization detected', impact: 'Reduced latency by 15%' },
      { timestamp: new Date().toISOString(), action: 'Cleaned Unused S3 Objects', reason: 'Storage free below 15%', impact: 'Saved $45.20/month' },
      { timestamp: new Date().toISOString(), action: 'Provisioned Reserved Instances', reason: 'Consistent long-term usage pattern', impact: 'Projected 40% cost reduction' }
    ];
    res.json(actions);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch actions' });
  }
});

// Chatbot endpoint (Mock LLM)
app.post('/api/chat', authenticate, async (req, res) => {
  const { query } = req.body;
  // Simplified logic to suggest cause
  let response = "Based on the telemetry data, there's a surge in traffic which might be the cause for the increased CPU utilization. I recommend checking the load balancer configuration and enabling auto-scaling.";
  if (query.toLowerCase().includes('cost')) {
    response = "The recent cost spike is primarily attributed to unoptimized storage volumes and cross-region data transfer fees. Consider enabling S3 Intelligent-Tiering and using CloudFront for content delivery.";
  }
  res.json({ response });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
