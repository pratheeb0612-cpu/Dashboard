const express = require('express');
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// IMPORTANT: Serve static files from current directory
app.use(express.static(path.join(__dirname)));

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Data storage (in production, use a proper database)
let dashboardData = {};
const dataFilePath = path.join(__dirname, 'data', 'dashboard_data.json');

// Admin credentials (in production, store in database with proper hashing)
const ADMIN_PASSWORD = 'admin123';

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel',
      'text/csv'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only Excel and CSV files are allowed.'));
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Initialize data storage
async function initializeDataStorage() {
  try {
    await fs.mkdir('data', { recursive: true });
    await fs.mkdir('uploads', { recursive: true });
    await fs.mkdir('templates', { recursive: true });
    
    try {
      const data = await fs.readFile(dataFilePath, 'utf8');
      dashboardData = JSON.parse(data);
      console.log('✅ Dashboard data loaded successfully');
    } catch (error) {
      // File doesn't exist, initialize with empty data
      dashboardData = {};
      await saveDashboardData();
      console.log('📝 Created new dashboard data file');
    }
  } catch (error) {
    console.error('Error initializing data storage:', error);
  }
}

// Save dashboard data to file
async function saveDashboardData() {
  try {
    await fs.writeFile(dataFilePath, JSON.stringify(dashboardData, null, 2));
  } catch (error) {
    console.error('Error saving dashboard data:', error);
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Entity configurations
const entities = [
  { 
    id: 'janashakthi-limited', 
    name: 'Janashakthi Limited', 
    shortName: 'JXG',
    description: 'Parent Entity'
  },
  { 
    id: 'janashakthi-insurance', 
    name: 'Janashakthi Insurance PLC', 
    shortName: 'JINS',
    description: 'Life Insurance'
  },
  { 
    id: 'first-capital', 
    name: 'First Capital Holdings PLC', 
    shortName: 'FCH',
    description: 'Investment Banking'
  },
  { 
    id: 'janashakthi-finance', 
    name: 'Janashakthi Finance PLC', 
    shortName: 'JF',
    description: 'Non-Financial Banking'
  }
];

// KPI Templates for each entity
const kpiTemplates = {
  'janashakthi-limited': [
    { name: 'Profit Before Tax', unit: 'LKR Mn' },
    { name: 'Finance Cost', unit: 'LKR Mn' },
    { name: 'Share of Profit from Subsidiaries', unit: 'LKR Mn' },
    { name: 'Debt to Equity Ratio', unit: 'x' },
    { name: 'ROE Annualized', unit: '%' },
    { name: 'Total Assets', unit: 'LKR Mn' },
    { name: 'Equity', unit: 'LKR Mn' },
    { name: 'Staff Count', unit: '' }
  ],
  'janashakthi-insurance': [
    { name: 'PAT', unit: 'LKR Mn' },
    { name: 'Gross Written Premium (GWP)', unit: 'LKR Mn' },
    { name: 'Total Assets', unit: 'LKR Mn' },
    { name: 'Investments', unit: 'LKR Mn' },
    { name: 'NAV', unit: 'LKR Mn' },
    { name: 'Total Liabilities', unit: 'LKR Mn' },
    { name: 'Insurance Provisions', unit: 'LKR Mn' },
    { name: 'ROE Annualized', unit: '%' },
    { name: 'Acquisition Cost as % of FYP', unit: '%' },
    { name: 'Cost + Claims + OH as % of GWP', unit: '%' },
    { name: 'Branches', unit: '' },
    { name: 'Staff Count', unit: '' }
  ],
  'first-capital': [
    { name: 'PAT', unit: 'LKR Mn' },
    { name: 'Total Assets', unit: 'LKR Mn' },
    { name: 'Financial Assets', unit: 'LKR Mn' },
    { name: 'Total Liabilities', unit: 'LKR Mn' },
    { name: 'Securities Sold', unit: 'LKR Mn' },
    { name: 'NAV', unit: 'LKR Mn' },
    { name: 'Investment Impairment', unit: 'LKR Mn' },
    { name: 'Debt to Equity Ratio', unit: 'x' },
    { name: 'ROI', unit: '%' },
    { name: 'PBT', unit: 'LKR Mn' },
    { name: 'ROE Annualized', unit: '%' },
    { name: 'ROA Annualized', unit: '%' },
    { name: 'Net Interest Income / Total Interest Income', unit: '%' },
    { name: 'Operating Cost to Income', unit: '%' }
  ],
  'janashakthi-finance': [
    { name: 'PAT', unit: 'LKR Mn' },
    { name: 'Total Assets', unit: 'LKR Mn' },
    { name: 'Fixed & Savings Deposits', unit: 'LKR Mn' },
    { name: 'Total Liabilities', unit: 'LKR Mn' },
    { name: 'Loans & Advances', unit: 'LKR Mn' },
    { name: 'NAV', unit: 'LKR Mn' },
    { name: 'Debt to Equity Ratio', unit: 'x' },
    { name: 'ROE Annualized', unit: '%' },
    { name: 'ROA Annualized', unit: '%' },
    { name: 'Net Interest Margin', unit: '%' },
    { name: 'Cost of Borrowings', unit: '%' },
    { name: 'Cost to Income Ratio', unit: '%' },
    { name: 'Branches', unit: '' },
    { name: 'Staff Count', unit: '' }
  ]
};

// Routes

// Health check (add this early for debugging)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    dataStatus: Object.keys(dashboardData).length > 0 ? 'Loaded' : 'Empty'
  });
});

// Authentication
app.post('/api/auth/login', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (password === ADMIN_PASSWORD) {
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ token, message: 'Authentication successful' });
    } else {
      res.status(401).json({ error: 'Invalid password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Get all dashboard data
app.get('/api/dashboard-data', (req, res) => {
  console.log('📊 Dashboard data requested, available periods:', Object.keys(dashboardData));
  res.json(dashboardData);
});

// Get specific entity data for a period
app.get('/api/dashboard-data/:entity/:month/:year', (req, res) => {
  const { entity, month, year } = req.params;
  
  const periodKey = `${month}-${year}`;
  const data = dashboardData[periodKey]?.[entity];
  
  if (data) {
    res.json(data);
  } else {
    res.status(404).json({ error: 'Data not found for specified period and entity' });
  }
});

// Get available periods
app.get('/api/periods', (req, res) => {
  const periods = Object.keys(dashboardData).map(periodKey => {
    const [month, year] = periodKey.split('-');
    return { month, year, key: periodKey };
  });
  
  res.json(periods);
});

// Download template
app.get('/api/template/:entityId', async (req, res) => {
  try {
    const { entityId } = req.params;
    const entity = entities.find(e => e.id === entityId);
    
    if (!entity) {
      return res.status(404).json({ error: 'Entity not found' });
    }

    const template = kpiTemplates[entityId];
    if (!template) {
      return res.status(404).json({ error: 'Template not found for entity' });
    }

    // Create Excel workbook
    const workbook = xlsx.utils.book_new();
    
    // KPI Sheet
    const kpiData = [
      ['KPI Name', 'Actual Value', 'Budget Value', 'Unit'],
      ...template.map(kpi => [kpi.name, '', '', kpi.unit])
    ];
    
    const kpiSheet = xlsx.utils.aoa_to_sheet(kpiData);
    xlsx.utils.book_append_sheet(workbook, kpiSheet, 'KPIs');

    // Generate file
    const fileName = `${entity.shortName}_Template_${Date.now()}.xlsx`;
    const filePath = path.join(__dirname, 'templates', fileName);
    
    xlsx.writeFile(workbook, filePath);
    
    res.download(filePath, `${entity.shortName}_Template.xlsx`, (err) => {
      if (err) {
        console.error('Error downloading file:', err);
      }
      // Clean up temporary file
      fs.unlink(filePath).catch(console.error);
    });

  } catch (error) {
    console.error('Error generating template:', error);
    res.status(500).json({ error: 'Failed to generate template' });
  }
});

// Upload data
app.post('/api/upload', authenticateToken, upload.single('dataFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { entityId, month, year } = req.body;
    
    if (!entityId || !month || !year) {
      return res.status(400).json({ error: 'Entity ID, month, and year are required' });
    }

    const entity = entities.find(e => e.id === entityId);
    if (!entity) {
      return res.status(400).json({ error: 'Invalid entity ID' });
    }

    // Read and parse Excel file
    const workbook = xlsx.readFile(req.file.path);
    const data = {};

    // Parse KPI data
    if (workbook.SheetNames.includes('KPIs')) {
      const kpiSheet = workbook.Sheets['KPIs'];
      const kpiData = xlsx.utils.sheet_to_json(kpiSheet, { header: 1 });
      
      data.kpis = [];
      
      // Skip header row
      for (let i = 1; i < kpiData.length; i++) {
        const row = kpiData[i];
        if (row[0] && (row[1] !== undefined || row[2] !== undefined)) {
          data.kpis.push({
            name: row[0],
            actual: parseFloat(row[1]) || null,
            budget: parseFloat(row[2]) || null,
            unit: row[3] || ''
          });
        }
      }
    }

    // Store data
    const periodKey = `${month}-${year}`;
    if (!dashboardData[periodKey]) {
      dashboardData[periodKey] = {};
    }
    dashboardData[periodKey][entityId] = data;

    // Save to file
    await saveDashboardData();

    // Clean up uploaded file
    await fs.unlink(req.file.path);

    res.json({ 
      message: 'Data uploaded successfully',
      entity: entity.name,
      period: `${month} ${year}`,
      dataKeys: Object.keys(data)
    });

  } catch (error) {
    console.error('Error processing upload:', error);
    
    // Clean up uploaded file in case of error
    if (req.file) {
      await fs.unlink(req.file.path).catch(console.error);
    }
    
    res.status(500).json({ error: 'Failed to process uploaded file' });
  }
});

// Delete data for specific period and entity
app.delete('/api/dashboard-data/:entity/:month/:year', authenticateToken, async (req, res) => {
  try {
    const { entity, month, year } = req.params;
    const periodKey = `${month}-${year}`;
    
    if (dashboardData[periodKey] && dashboardData[periodKey][entity]) {
      delete dashboardData[periodKey][entity];
      
      // If no entities left for this period, delete the period
      if (Object.keys(dashboardData[periodKey]).length === 0) {
        delete dashboardData[periodKey];
      }
      
      await saveDashboardData();
      res.json({ message: 'Data deleted successfully' });
    } else {
      res.status(404).json({ error: 'Data not found' });
    }
  } catch (error) {
    console.error('Error deleting data:', error);
    res.status(500).json({ error: 'Failed to delete data' });
  }
});

// Get entities list
app.get('/api/entities', (req, res) => {
  res.json(entities);
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
async function startServer() {
  await initializeDataStorage();
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Dashboard available at http://localhost:${PORT}`);
    console.log(`📊 Dashboard API available at http://localhost:${PORT}/api`);
    console.log(`🔑 Admin password: ${ADMIN_PASSWORD}`);
    console.log(`📁 Static files served from: ${__dirname}`);
  });
}

startServer().catch(console.error);

module.exports = app;