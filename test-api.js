const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const API_BASE_URL = 'http://localhost:3001/api';
const ADMIN_PASSWORD = 'admin123';

let authToken = null;

// Color codes for console output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bright: '\x1b[1m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, 'green');
}

function logError(message) {
  log(`❌ ${message}`, 'red');
}

function logInfo(message) {
  log(`ℹ️  ${message}`, 'blue');
}

function logWarning(message) {
  log(`⚠️  ${message}`, 'yellow');
}

// Test functions
async function testHealthCheck() {
  try {
    log('\n🔍 Testing Health Check...', 'cyan');
    const response = await axios.get(`${API_BASE_URL}/health`);
    logSuccess(`Health check passed: ${response.data.status}`);
    return true;
  } catch (error) {
    logError(`Health check failed: ${error.message}`);
    return false;
  }
}

async function testAuthentication() {
  try {
    log('\n🔐 Testing Authentication...', 'cyan');
    
    // Test with correct password
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      password: ADMIN_PASSWORD
    });
    
    authToken = response.data.token;
    logSuccess('Authentication successful');
    logInfo(`Token received: ${authToken.substring(0, 20)}...`);

    // Test with wrong password
    try {
      await axios.post(`${API_BASE_URL}/auth/login`, {
        password: 'wrongpassword'
      });
      logWarning('Wrong password test failed - should have been rejected');
    } catch (error) {
      if (error.response?.status === 401) {
        logSuccess('Wrong password correctly rejected');
      }
    }

    return true;
  } catch (error) {
    logError(`Authentication failed: ${error.response?.data?.error || error.message}`);
    return false;
  }
}

async function testGetEntities() {
  try {
    log('\n🏢 Testing Get Entities...', 'cyan');
    const response = await axios.get(`${API_BASE_URL}/entities`);
    logSuccess(`Retrieved ${response.data.length} entities`);
    
    response.data.forEach(entity => {
      log(`   - ${entity.name} (${entity.shortName})`, 'reset');
    });
    
    return true;
  } catch (error) {
    logError(`Get entities failed: ${error.message}`);
    return false;
  }
}

async function testGetDashboardData() {
  try {
    log('\n📊 Testing Get Dashboard Data...', 'cyan');
    const response = await axios.get(`${API_BASE_URL}/dashboard-data`);
    
    const periods = Object.keys(response.data);
    logSuccess(`Retrieved dashboard data for ${periods.length} periods`);
    
    periods.forEach(period => {
      const entities = Object.keys(response.data[period]);
      log(`   - ${period}: ${entities.length} entities`, 'reset');
    });
    
    return true;
  } catch (error) {
    logError(`Get dashboard data failed: ${error.message}`);
    return false;
  }
}

async function testGetPeriods() {
  try {
    log('\n📅 Testing Get Periods...', 'cyan');
    const response = await axios.get(`${API_BASE_URL}/periods`);
    logSuccess(`Retrieved ${response.data.length} available periods`);
    
    response.data.forEach(period => {
      log(`   - ${period.month} ${period.year}`, 'reset');
    });
    
    return true;
  } catch (error) {
    logError(`Get periods failed: ${error.message}`);
    return false;
  }
}

async function testDownloadTemplate() {
  try {
    log('\n📋 Testing Template Download...', 'cyan');
    
    const entityId = 'janashakthi-limited';
    const response = await axios.get(`${API_BASE_URL}/template/${entityId}`, {
      responseType: 'arraybuffer'
    });
    
    // Save the file temporarily
    const tempPath = path.join(__dirname, 'temp_template.xlsx');
    fs.writeFileSync(tempPath, response.data);
    
    const stats = fs.statSync(tempPath);
    logSuccess(`Template downloaded successfully (${stats.size} bytes)`);
    
    // Clean up
    fs.unlinkSync(tempPath);
    
    return true;
  } catch (error) {
    logError(`Template download failed: ${error.message}`);
    return false;
  }
}

async function testFileUpload() {
  try {
    log('\n📤 Testing File Upload...', 'cyan');
    
    if (!authToken) {
      logWarning('No auth token available, skipping upload test');
      return false;
    }

    // Check if sample file exists
    const sampleFilePath = path.join(__dirname, 'sample-uploads', 'JXG_Sample_August_2025.xlsx');
    
    if (!fs.existsSync(sampleFilePath)) {
      logWarning('Sample file not found, creating a simple test file...');
      
      // Create a simple CSV for testing
      const csvContent = `KPI Name,Actual Value,Budget Value,Unit
Profit Before Tax,200,180,LKR Mn
Total Assets,6500,6000,LKR Mn
ROE Annualized,28,25,%`;
      
      const testFilePath = path.join(__dirname, 'test_upload.csv');
      fs.writeFileSync(testFilePath, csvContent);
      
      const formData = new FormData();
      formData.append('dataFile', fs.createReadStream(testFilePath));
      formData.append('entityId', 'janashakthi-limited');
      formData.append('month', 'August');
      formData.append('year', '2025');

      const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          ...formData.getHeaders()
        }
      });

      logSuccess('File upload successful');
      logInfo(`Response: ${response.data.message}`);
      
      // Clean up test file
      fs.unlinkSync(testFilePath);
      
    } else {
      // Use existing sample file
      const formData = new FormData();
      formData.append('dataFile', fs.createReadStream(sampleFilePath));
      formData.append('entityId', 'janashakthi-limited');
      formData.append('month', 'August');
      formData.append('year', '2025');

      const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          ...formData.getHeaders()
        }
      });

      logSuccess('Sample Excel file upload successful');
      logInfo(`Response: ${response.data.message}`);
    }
    
    return true;
  } catch (error) {
    logError(`File upload failed: ${error.response?.data?.error || error.message}`);
    return false;
  }
}

async function testSpecificEntityData() {
  try {
    log('\n🎯 Testing Specific Entity Data Retrieval...', 'cyan');
    
    const response = await axios.get(`${API_BASE_URL}/dashboard-data/janashakthi-limited/June/2025`);
    
    logSuccess('Retrieved specific entity data');
    logInfo(`Entity: Janashakthi Limited`);
    logInfo(`Period: June 2025`);
    logInfo(`KPIs: ${response.data.kpis?.length || 0}`);
    
    if (response.data.kpis && response.data.kpis.length > 0) {
      log('   Sample KPIs:', 'reset');
      response.data.kpis.slice(0, 3).forEach(kpi => {
        log(`   - ${kpi.name}: ${kpi.actual} ${kpi.unit}`, 'reset');
      });
    }
    
    return true;
  } catch (error) {
    logError(`Get specific entity data failed: ${error.response?.data?.error || error.message}`);
    return false;
  }
}

async function testUnauthorizedAccess() {
  try {
    log('\n🚫 Testing Unauthorized Access...', 'cyan');
    
    const csvContent = `KPI Name,Actual Value,Budget Value,Unit
Test KPI,100,90,LKR Mn`;
    
    const testFilePath = path.join(__dirname, 'unauthorized_test.csv');
    fs.writeFileSync(testFilePath, csvContent);
    
    const formData = new FormData();
    formData.append('dataFile', fs.createReadStream(testFilePath));
    formData.append('entityId', 'janashakthi-limited');
    formData.append('month', 'September');
    formData.append('year', '2025');

    try {
      await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          // No Authorization header
          ...formData.getHeaders()
        }
      });
      logWarning('Unauthorized access test failed - should have been rejected');
    } catch (error) {
      if (error.response?.status === 401) {
        logSuccess('Unauthorized access correctly rejected');
      } else {
        logWarning(`Unexpected error: ${error.response?.status}`);
      }
    }
    
    // Clean up
    fs.unlinkSync(testFilePath);
    
    return true;
  } catch (error) {
    logError(`Unauthorized access test failed: ${error.message}`);
    return false;
  }
}

async function testInvalidFileUpload() {
  try {
    log('\n📄 Testing Invalid File Upload...', 'cyan');
    
    if (!authToken) {
      logWarning('No auth token available, skipping invalid file test');
      return false;
    }

    // Create an invalid file (text file instead of Excel/CSV)
    const invalidContent = 'This is not a valid Excel or CSV file';
    const invalidFilePath = path.join(__dirname, 'invalid_file.txt');
    fs.writeFileSync(invalidFilePath, invalidContent);
    
    const formData = new FormData();
    formData.append('dataFile', fs.createReadStream(invalidFilePath));
    formData.append('entityId', 'janashakthi-limited');
    formData.append('month', 'September');
    formData.append('year', '2025');

    try {
      await axios.post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          ...formData.getHeaders()
        }
      });
      logWarning('Invalid file upload test failed - should have been rejected');
    } catch (error) {
      if (error.response?.status === 400) {
        logSuccess('Invalid file correctly rejected');
        logInfo(`Error message: ${error.response.data.error}`);
      } else {
        logWarning(`Unexpected error: ${error.response?.status}`);
      }
    }
    
    // Clean up
    fs.unlinkSync(invalidFilePath);
    
    return true;
  } catch (error) {
    logError(`Invalid file upload test failed: ${error.message}`);
    return false;
  }
}

async function testPerformanceMetrics() {
  try {
    log('\n⚡ Testing Performance Metrics...', 'cyan');
    
    const startTime = Date.now();
    
    // Test multiple concurrent requests
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(axios.get(`${API_BASE_URL}/dashboard-data`));
    }
    
    await Promise.all(promises);
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    logSuccess(`5 concurrent requests completed in ${duration}ms`);
    logInfo(`Average response time: ${(duration / 5).toFixed(2)}ms`);
    
    if (duration < 5000) {
      logSuccess('Performance test passed (< 5 seconds)');
    } else {
      logWarning('Performance test slow (> 5 seconds)');
    }
    
    return true;
  } catch (error) {
    logError(`Performance test failed: ${error.message}`);
    return false;
  }
}

// Main test runner
async function runAllTests() {
  log('🧪 Starting API Test Suite', 'bright');
  log('================================', 'cyan');
  
  const tests = [
    { name: 'Health Check', fn: testHealthCheck },
    { name: 'Authentication', fn: testAuthentication },
    { name: 'Get Entities', fn: testGetEntities },
    { name: 'Get Dashboard Data', fn: testGetDashboardData },
    { name: 'Get Periods', fn: testGetPeriods },
    { name: 'Download Template', fn: testDownloadTemplate },
    { name: 'File Upload', fn: testFileUpload },
    { name: 'Specific Entity Data', fn: testSpecificEntityData },
    { name: 'Unauthorized Access', fn: testUnauthorizedAccess },
    { name: 'Invalid File Upload', fn: testInvalidFileUpload },
    { name: 'Performance Metrics', fn: testPerformanceMetrics }
  ];
  
  const results = {
    passed: 0,
    failed: 0,
    total: tests.length
  };
  
  for (const test of tests) {
    try {
      const success = await test.fn();
      if (success) {
        results.passed++;
      } else {
        results.failed++;
      }
    } catch (error) {
      logError(`Test "${test.name}" threw an error: ${error.message}`);
      results.failed++;
    }
    
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  // Print summary
  log('\n📊 Test Results Summary', 'bright');
  log('================================', 'cyan');
  log(`Total Tests: ${results.total}`, 'blue');
  log(`Passed: ${results.passed}`, 'green');
  log(`Failed: ${results.failed}`, results.failed > 0 ? 'red' : 'green');
  log(`Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%`, 
      results.failed === 0 ? 'green' : 'yellow');
  
  if (results.failed === 0) {
    log('\n🎉 All tests passed! Your API is working correctly.', 'green');
  } else {
    log('\n⚠️  Some tests failed. Check the logs above for details.', 'yellow');
  }
  
  log('\n💡 Next steps:', 'cyan');
  log('   1. If tests passed, your backend is ready!');
  log('   2. Try the frontend at http://localhost:3001');
  log('   3. Upload sample files from sample-uploads/ folder');
  log('   4. Check dashboard data visualization');
}

// Test individual functions
async function testSpecificFunction(functionName) {
  const testMap = {
    'health': testHealthCheck,
    'auth': testAuthentication,
    'entities': testGetEntities,
    'data': testGetDashboardData,
    'periods': testGetPeriods,
    'template': testDownloadTemplate,
    'upload': testFileUpload,
    'specific': testSpecificEntityData,
    'unauthorized': testUnauthorizedAccess,
    'invalid': testInvalidFileUpload,
    'performance': testPerformanceMetrics
  };
  
  const testFn = testMap[functionName.toLowerCase()];
  if (!testFn) {
    logError(`Unknown test function: ${functionName}`);
    log('Available tests: ' + Object.keys(testMap).join(', '), 'info');
    return;
  }
  
  log(`🧪 Running single test: ${functionName}`, 'bright');
  log('================================', 'cyan');
  
  try {
    // Run authentication first if needed
    if (functionName !== 'health' && functionName !== 'auth' && functionName !== 'entities') {
      await testAuthentication();
    }
    
    const success = await testFn();
    if (success) {
      logSuccess(`Test "${functionName}" passed!`);
    } else {
      logError(`Test "${functionName}" failed!`);
    }
  } catch (error) {
    logError(`Test "${functionName}" threw an error: ${error.message}`);
  }
}

// Command line interface
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    runAllTests().catch(console.error);
  } else if (args[0] === '--test' && args[1]) {
    testSpecificFunction(args[1]).catch(console.error);
  } else {
    log('Usage:', 'cyan');
    log('  node test-api.js                    # Run all tests');
    log('  node test-api.js --test <function>  # Run specific test');
    log('');
    log('Available test functions:', 'cyan');
    log('  health, auth, entities, data, periods, template,');
    log('  upload, specific, unauthorized, invalid, performance');
  }
}

module.exports = {
  runAllTests,
  testSpecificFunction,
  testHealthCheck,
  testAuthentication,
  testGetEntities,
  testGetDashboardData,
  testGetPeriods,
  testDownloadTemplate,
  testFileUpload,
  testSpecificEntityData,
  testUnauthorizedAccess,
  testInvalidFileUpload,
  testPerformanceMetrics
};