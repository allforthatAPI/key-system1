// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const { init } = require('./db/init');
const validateRoute = require('./routes/validate');
const adminAuthRoute = require('./routes/adminAuth');
const adminRoute = require('./routes/admin');

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Public: called by the protected C++/C# software
app.use('/api', validateRoute);

// Admin auth + management
app.use('/api/admin/auth', adminAuthRoute);
app.use('/api/admin', adminRoute);

// Serve the dashboard (static frontend)
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;

init()
  .then(() => {
    app.listen(PORT, () => console.log(`Saturn key system listening on :${PORT}`));
  })
  .catch(err => {
    console.error('Failed to init database', err);
    process.exit(1);
  });
