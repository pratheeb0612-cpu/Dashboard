const fs = require('fs').promises;
const path = require('path');

// Sample dashboard data for testing
const sampleData = {
  "June-2025": {
    "janashakthi-limited": {
      kpis: [
        { name: 'Profit Before Tax', actual: 150, budget: 120, unit: 'LKR Mn' },
        { name: 'Finance Cost', actual: 18, budget: 20, unit: 'LKR Mn' },
        { name: 'Share of Profit from Subsidiaries', actual: 125, budget: 100, unit: 'LKR Mn' },
        { name: 'Debt to Equity Ratio', actual: 1.15, budget: 1.20, unit: 'x' },
        { name: 'ROE Annualized', actual: 22, budget: 18, unit: '%' },
        { name: 'Total Assets', actual: 5500, budget: 5200, unit: 'LKR Mn' },
        { name: 'Equity', actual: 1800, budget: 1650, unit: 'LKR Mn' },
        { name: 'Staff Count', actual: 258, budget: 250, unit: '' }
      ],
      shareComposition: [
        { name: 'Janashakthi Insurance PLC', value: 38, color: '#8B5CF6' },
        { name: 'First Capital Holdings PLC', value: 32, color: '#06B6D4' },
        { name: 'Janashakthi Finance PLC', value: 30, color: '#10B981' }
      ],
      overheads: [
        { category: 'Staff Cost', actual: 95, budget: 100 },
        { category: 'Admin Cost', actual: 110, budget: 100 },
        { category: 'Marketing', actual: 85, budget: 100 },
        { category: 'Professional Charges', actual: 75, budget: 100 }
      ]
    },
    "janashakthi-insurance": {
      kpis: [
        { name: 'PAT', actual: 1200, budget: 1000, unit: 'LKR Mn' },
        { name: 'Gross Written Premium (GWP)', actual: 1150, budget: 1000, unit: 'LKR Mn' },
        { name: 'Total Assets', actual: 13500, budget: 12000, unit: 'LKR Mn' },
        { name: 'Investments', actual: 12800, budget: 12000, unit: 'LKR Mn' },
        { name: 'NAV', actual: 13200, budget: 12000, unit: 'LKR Mn' },
        { name: 'Total Liabilities', actual: 11700, budget: 12000, unit: 'LKR Mn' },
        { name: 'Insurance Provisions', actual: 11500, budget: 12000, unit: 'LKR Mn' },
        { name: 'ROE Annualized', actual: 18, budget: 15, unit: '%' },
        { name: 'Acquisition Cost as % of FYP', actual: 85, budget: 90, unit: '%' },
        { name: 'Cost + Claims + OH as % of GWP', actual: 88, budget: 90, unit: '%' },
        { name: 'Branches', actual: 12, budget: 10, unit: '' },
        { name: 'Staff Count', actual: 145, budget: 130, unit: '' }
      ],
      retailBusinessFYP: [
        { month: '25-Apr', actual: 85, budget: 80 },
        { month: '25-May', actual: 92, budget: 85 },
        { month: '25-Jun', actual: 105, budget: 90 }
      ],
      jsvFYP: [
        { month: '25-Apr', actual: 75, budget: 80 },
        { month: '25-May', actual: 88, budget: 85 },
        { month: '25-Jun', actual: 95, budget: 90 }
      ],
      dtaFYP: [
        { month: '25-Apr', actual: 65, budget: 70 },
        { month: '25-May', actual: 78, budget: 75 },
        { month: '25-Jun', actual: 82, budget: 80 }
      ],
      renewalPremium: [
        { month: '25-Apr', actual: 120, budget: 110 },
        { month: '25-May', actual: 135, budget: 125 },
        { month: '25-Jun', actual: 145, budget: 130 }
      ],
      ulCreditRating: [
        { month: '25-Apr', actual: 8.5, budget: 8.0 },
        { month: '25-May', actual: 8.8, budget: 8.2 },
        { month: '25-Jun', actual: 9.2, budget: 8.5 }
      ],
      surplusActual: [
        { month: '25-Apr', actual: 25, budget: 20 },
        { month: '25-May', actual: 32, budget: 25 },
        { month: '25-Jun', actual: 38, budget: 30 }
      ]
    },
    "first-capital": {
      kpis: [
        { name: 'PAT', actual: 1100, budget: 900, unit: 'LKR Mn' },
        { name: 'Total Assets', actual: 13200, budget: 12000, unit: 'LKR Mn' },
        { name: 'Financial Assets', actual: 12500, budget: 12000, unit: 'LKR Mn' },
        { name: 'Total Liabilities', actual: 11800, budget: 12000, unit: 'LKR Mn' },
        { name: 'Securities Sold', actual: 11500, budget: 12000, unit: 'LKR Mn' },
        { name: 'NAV', actual: 12800, budget: 12000, unit: 'LKR Mn' },
        { name: 'Investment Impairment', actual: 4800, budget: 5000, unit: 'LKR Mn' },
        { name: 'Debt to Equity Ratio', actual: 1.05, budget: 1.19, unit: 'x' },
        { name: 'ROI', actual: 320, budget: 300, unit: '%' },
        { name: 'PBT', actual: 1150, budget: 1000, unit: 'LKR Mn' },
        { name: 'ROE Annualized', actual: 115, budget: 100, unit: '%' },
        { name: 'ROA Annualized', actual: 108, budget: 100, unit: '%' },
        { name: 'Net Interest Income / Total Interest Income', actual: 12, budget: 10, unit: '%' },
        { name: 'Operating Cost to Income', actual: 8, budget: 10, unit: '%' }
      ],
      netIncomeAgainstBudget: [
        { month: '25-Apr', actual: 95, budget: 90 },
        { month: '25-May', actual: 105, budget: 95 },
        { month: '25-Jun', actual: 115, budget: 100 }
      ],
      tradingComposition: [
        { name: 'Primary Dealing', value: 120, color: '#8B5CF6' },
        { name: 'Dealing Securities', value: 110, color: '#06B6D4' },
        { name: 'Corporate Finance', value: 95, color: '#10B981' },
        { name: 'Asset Management', value: 85, color: '#F59E0B' },
        { name: 'Stock Brokering', value: 75, color: '#EF4444' }
      ],
      overheadsAgainstBudget: [
        { category: 'Staff Cost', actual: 105, budget: 100 },
        { category: 'Admin Cost', actual: 95, budget: 100 },
        { category: 'Marketing', actual: 110, budget: 100 },
        { category: 'Professional Charges', actual: 88, budget: 100 }
      ],
      unitTrustAUM: [
        { month: '25-Apr', actual: 71000, budget: 70000 },
        { month: '25-May', actual: 74000, budget: 72000 },
        { month: '25-Jun', actual: 76000, budget: 73000 }
      ],
      wmAUM: [
        { month: '25-Apr', actual: 72000, budget: 70000 },
        { month: '25-May', actual: 75000, budget: 72000 },
        { month: '25-Jun', actual: 78000, budget: 73000 }
      ],
      treasuries: [
        { month: '25-Apr', tBills: 28000, outrightSale: 52000, govSecurities: 82000 },
        { month: '25-May', tBills: 32000, outrightSale: 58000, govSecurities: 85000 },
        { month: '25-Jun', tBills: 35000, outrightSale: 60000, govSecurities: 88000 }
      ],
      dealingSecurities: [
        { category: 'Investment in Corporate & Gov Debts', jun: 5200, jul: 4800, aug: 6200 },
        { category: 'MTM Gain/Loss on Corporate & Gov. Debts', jun: -28, jul: -22, aug: 35 },
        { category: 'Investment in Listed Equity Securities FVTPL', jun: 5200, jul: 5000, aug: 5300 },
        { category: 'MTM Gain/Loss on Listed Equity Securities FVTPL', jun: 3600, jul: 3400, aug: 3700 },
        { category: 'Investment in Listed Equity Securities FVTOCI', jun: 2600, jul: 2400, aug: 2700 },
        { category: 'MTM Gain/Loss on Listed Equity Securities FVTOCI', jun: 78, jul: 68, aug: 85 },
        { category: 'Value of Debt Mandates executed for the Month', jun: 12, jul: 8, aug: 15 }
      ],
      equitiesTurnover: [
        { month: '25-Apr', transactionVolume: 4.25, commissionBased: 3.8 },
        { month: '25-May', transactionVolume: 4.45, commissionBased: 4.1 },
        { month: '25-Jun', transactionVolume: 4.60, commissionBased: 4.2 }
      ],
      portfolioManagement: [
        { month: '25-Apr', value: 37000 },
        { month: '25-May', value: 39000 },
        { month: '25-Jun', value: 41000 }
      ]
    },
    "janashakthi-finance": {
      kpis: [
        { name: 'PAT', actual: 950, budget: 800, unit: 'LKR Mn' },
        { name: 'Total Assets', actual: 11800, budget: 12000, unit: 'LKR Mn' },
        { name: 'Fixed & Savings Deposits', actual: 11500, budget: 12000, unit: 'LKR Mn' },
        { name: 'Total Liabilities', actual: 10200, budget: 12000, unit: 'LKR Mn' },
        { name: 'Loans & Advances', actual: 10800, budget: 12000, unit: 'LKR Mn' },
        { name: 'NAV', actual: 11200, budget: 12000, unit: 'LKR Mn' },
        { name: 'Debt to Equity Ratio', actual: 1.08, budget: 1.19, unit: 'x' },
        { name: 'ROE Annualized', actual: 112, budget: 100, unit: '%' },
        { name: 'ROA Annualized', actual: 105, budget: 100, unit: '%' },
        { name: 'Net Interest Margin', actual: 11.5, budget: 10, unit: '%' },
        { name: 'Cost of Borrowings', actual: 8.5, budget: 9, unit: '%' },
        { name: 'Cost to Income Ratio', actual: 55, budget: 60, unit: '%' },
        { name: 'Branches', actual: 11, budget: 10, unit: '' },
        { name: 'Staff Count', actual: 142, budget: 130, unit: '' }
      ],
      netInterestIncomeAgainstBudget: [
        { month: '25-Apr', actual: 88, budget: 85 },
        { month: '25-May', actual: 95, budget: 90 },
        { month: '25-Jun', actual: 102, budget: 95 }
      ],
      loanComposition: [
        { name: 'Factoring', value: 115, color: '#8B5CF6' },
        { name: 'Gold Loans', value: 105, color: '#06B6D4' },
        { name: 'Leasing', value: 95, color: '#10B981' },
        { name: 'Loans', value: 85, color: '#F59E0B' },
        { name: 'Ijara', value: 70, color: '#EF4444' }
      ],
      overheadsAgainstBudget: [
        { category: 'Staff Cost', actual: 92, budget: 100 },
        { category: 'Admin Cost', actual: 88, budget: 100 },
        { category: 'Marketing', actual: 105, budget: 100 },
        { category: 'Professional Charges', actual: 78, budget: 100 }
      ],
      businessActivity: [
        { month: '25-Apr', newFDs: 285, fdsWithdrawn: 180, otherLoans: 140, goldLoans: 11200 },
        { month: '25-May', newFDs: 310, fdsWithdrawn: 220, otherLoans: 480, goldLoans: 10800 },
        { month: '25-Jun', newFDs: 325, fdsWithdrawn: 260, otherLoans: 185, goldLoans: 11100 }
      ]
    }
  },
  "May-2025": {
    "janashakthi-limited": {
      kpis: [
        { name: 'Profit Before Tax', actual: 125, budget: 120, unit: 'LKR Mn' },
        { name: 'Finance Cost', actual: 16, budget: 20, unit: 'LKR Mn' },
        { name: 'Share of Profit from Subsidiaries', actual: 110, budget: 100, unit: 'LKR Mn' },
        { name: 'Debt to Equity Ratio', actual: 1.18, budget: 1.20, unit: 'x' },
        { name: 'ROE Annualized', actual: 20, budget: 18, unit: '%' },
        { name: 'Total Assets', actual: 5200, budget: 5200, unit: 'LKR Mn' },
        { name: 'Equity', actual: 1650, budget: 1650, unit: 'LKR Mn' },
        { name: 'Staff Count', actual: 252, budget: 250, unit: '' }
      ]
    },
    "janashakthi-insurance": {
      kpis: [
        { name: 'PAT', actual: 950, budget: 1000, unit: 'LKR Mn' },
        { name: 'Gross Written Premium (GWP)', actual: 980, budget: 1000, unit: 'LKR Mn' },
        { name: 'Total Assets', actual: 12800, budget: 12000, unit: 'LKR Mn' },
        { name: 'ROE Annualized', actual: 16, budget: 15, unit: '%' },
        { name: 'Branches', actual: 11, budget: 10, unit: '' },
        { name: 'Staff Count', actual: 138, budget: 130, unit: '' }
      ]
    }
  },
  "July-2025": {
    "janashakthi-limited": {
      kpis: [
        { name: 'Profit Before Tax', actual: 0, budget: 140, unit: 'LKR Mn' },
        { name: 'Finance Cost', actual: 0, budget: 22, unit: 'LKR Mn' },
        { name: 'Share of Profit from Subsidiaries', actual: 0, budget: 110, unit: 'LKR Mn' },
        { name: 'Debt to Equity Ratio', actual: 0, budget: 1.15, unit: 'x' },
        { name: 'ROE Annualized', actual: 0, budget: 20, unit: '%' },
        { name: 'Total Assets', actual: 0, budget: 5800, unit: 'LKR Mn' },
        { name: 'Equity', actual: 0, budget: 1900, unit: 'LKR Mn' },
        { name: 'Staff Count', actual: 0, budget: 260, unit: '' }
      ]
    }
  }
};

// Function to seed the database with sample data
async function seedSampleData() {
  try {
    // Ensure data directory exists
    const dataDir = path.join(__dirname, 'data');
    await fs.mkdir(dataDir, { recursive: true });

    // Write sample data to file
    const dataFilePath = path.join(dataDir, 'dashboard_data.json');
    await fs.writeFile(dataFilePath, JSON.stringify(sampleData, null, 2));

    console.log('✅ Sample data seeded successfully!');
    console.log('📊 Available periods:');
    Object.keys(sampleData).forEach(period => {
      console.log(`   - ${period}`);
      Object.keys(sampleData[period]).forEach(entity => {
        console.log(`     └── ${entity} (${sampleData[period][entity].kpis?.length || 0} KPIs)`);
      });
    });

    return sampleData;
  } catch (error) {
    console.error('❌ Error seeding sample data:', error);
    throw error;
  }
}

// Generate sample Excel files for testing
async function generateSampleExcelFiles() {
  try {
    const xlsx = require('xlsx');
    const templatesDir = path.join(__dirname, 'sample-uploads');
    await fs.mkdir(templatesDir, { recursive: true });

    // Sample data for Janashakthi Limited
    const jxgData = {
      'KPIs': [
        ['KPI Name', 'Actual Value', 'Budget Value', 'Unit'],
        ['Profit Before Tax', 180, 140, 'LKR Mn'],
        ['Finance Cost', 20, 22, 'LKR Mn'],
        ['Share of Profit from Subsidiaries', 140, 110, 'LKR Mn'],
        ['Debt to Equity Ratio', 1.1, 1.15, 'x'],
        ['ROE Annualized', 25, 20, '%'],
        ['Total Assets', 6000, 5800, 'LKR Mn'],
        ['Equity', 2000, 1900, 'LKR Mn'],
        ['Staff Count', 265, 260, '']
      ],
      'Share Composition': [
        ['Entity', 'Percentage'],
        ['Janashakthi Insurance PLC', 40],
        ['First Capital Holdings PLC', 35],
        ['Janashakthi Finance PLC', 25]
      ],
      'Overheads': [
        ['Category', 'Actual', 'Budget'],
        ['Staff Cost', 105, 100],
        ['Admin Cost', 90, 100],
        ['Marketing', 120, 100],
        ['Professional Charges', 85, 100]
      ]
    };

    // Create workbook for JXG
    const jxgWorkbook = xlsx.utils.book_new();
    Object.entries(jxgData).forEach(([sheetName, data]) => {
      const worksheet = xlsx.utils.aoa_to_sheet(data);
      xlsx.utils.book_append_sheet(jxgWorkbook, worksheet, sheetName);
    });

    // Save JXG file
    const jxgFilePath = path.join(templatesDir, 'JXG_Sample_August_2025.xlsx');
    xlsx.writeFile(jxgWorkbook, jxgFilePath);

    // Sample data for Janashakthi Insurance
    const jinsData = {
      'KPIs': [
        ['KPI Name', 'Actual Value', 'Budget Value', 'Unit'],
        ['PAT', 1300, 1200, 'LKR Mn'],
        ['Gross Written Premium (GWP)', 1250, 1200, 'LKR Mn'],
        ['Total Assets', 14000, 13000, 'LKR Mn'],
        ['ROE Annualized', 20, 18, '%'],
        ['Branches', 13, 12, ''],
        ['Staff Count', 155, 145, '']
      ],
      'Retail Business FYP': [
        ['Month', 'Actual', 'Budget'],
        ['25-May', 95, 90],
        ['25-Jun', 105, 95],
        ['25-Jul', 115, 100]
      ],
      'JSV FYP': [
        ['Month', 'Actual', 'Budget'],
        ['25-May', 85, 90],
        ['25-Jun', 95, 95],
        ['25-Jul', 105, 100]
      ]
    };

    const jinsWorkbook = xlsx.utils.book_new();
    Object.entries(jinsData).forEach(([sheetName, data]) => {
      const worksheet = xlsx.utils.aoa_to_sheet(data);
      xlsx.utils.book_append_sheet(jinsWorkbook, worksheet, sheetName);
    });

    const jinsFilePath = path.join(templatesDir, 'JINS_Sample_August_2025.xlsx');
    xlsx.writeFile(jinsWorkbook, jinsFilePath);

    console.log('📁 Sample Excel files created:');
    console.log(`   - ${jxgFilePath}`);
    console.log(`   - ${jinsFilePath}`);

  } catch (error) {
    console.error('❌ Error generating sample Excel files:', error);
  }
}

// Main function to set up training environment
async function setupTrainingEnvironment() {
  console.log('🏗️  Setting up training environment...\n');

  try {
    // Create necessary directories
    const dirs = ['data', 'uploads', 'templates', 'logs', 'sample-uploads'];
    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
      console.log(`📁 Created directory: ${dir}/`);
    }

    // Seed sample data
    console.log('\n📊 Seeding sample data...');
    await seedSampleData();

    // Generate sample Excel files
    console.log('\n📋 Generating sample Excel files...');
    await generateSampleExcelFiles();

    console.log('\n🎉 Training environment setup complete!');
    console.log('\n🚀 Next steps:');
    console.log('   1. Run "npm install" to install dependencies');
    console.log('   2. Run "npm run dev" to start the server');
    console.log('   3. Open http://localhost:3001 in your browser');
    console.log('   4. Use password "admin123" to access Data Manager');
    console.log('   5. Upload sample Excel files from sample-uploads/ folder');
    console.log('\n💡 Available test data:');
    console.log('   - June 2025: Complete data for all entities');
    console.log('   - May 2025: Partial data for some entities');
    console.log('   - July 2025: Budget-only data (for testing uploads)');

  } catch (error) {
    console.error('❌ Setup failed:', error);
    process.exit(1);
  }
}

// Export functions for use in other files
module.exports = {
  seedSampleData,
  generateSampleExcelFiles,
  setupTrainingEnvironment,
  sampleData
};

// Run setup if this file is executed directly
if (require.main === module) {
  setupTrainingEnvironment();
}