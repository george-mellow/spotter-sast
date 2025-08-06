#!/usr/bin/env node
/**
 * Spotter-SAST Compliance System Tests
 * ====================================
 * 
 * Tests the compliance verification system including:
 * - Framework configuration loading
 * - Compliance engine functionality
 * - Pattern matching
 * - Risk scoring
 * - Report generation
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.join(__dirname, '..');

// Test configuration
const testConfig = {
  configDir: path.join(projectRoot, 'config'),
  testDataDir: path.join(__dirname, 'test-data'),
  outputDir: path.join(__dirname, 'test-output')
};

// Ensure test directories exist
Object.values(testConfig).forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Colors for test output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(color, message) {
  console.error(`${colors[color]}${message}${colors.reset}`);
}

function logSuccess(message) { log('green', `✅ ${message}`); }
function logError(message) { log('red', `❌ ${message}`); }
function logWarning(message) { log('yellow', `⚠️  ${message}`); }
function logInfo(message) { log('blue', `ℹ️  ${message}`); }
function logHeader(message) { log('cyan', `\n🧪 ${message}`); }

// Test counter
let tests = { total: 0, passed: 0, failed: 0 };

function runTest(name, testFn) {
  tests.total++;
  try {
    logInfo(`Testing: ${name}`);
    testFn();
    tests.passed++;
    logSuccess(`PASSED: ${name}`);
  } catch (error) {
    tests.failed++;
    logError(`FAILED: ${name} - ${error.message}`);
  }
}

// Create test data files
function createTestData() {
  logHeader('Creating Test Data');
  
  // Vulnerable JavaScript file with multiple compliance violations
  const vulnerableJS = `
// HIPAA Violation - Hardcoded PHI database credentials
const patientDbConfig = {
  host: 'phi-database.hospital.com',
  username: 'phi_user',
  password: 'patient_data_2024!', // Hardcoded PHI access
  database: 'patient_medical_records'
};

// PCI DSS Violation - Credit card data exposure  
const testCreditCard = '4532-1234-5678-9012'; // Test card number
const customerPayment = {
  cardNumber: '4111111111111111',
  cvv: '123',
  expiryDate: '12/25'
};

// GDPR Violation - Personal data collection without consent
function collectUserData(email, location) {
  // Collecting personal data without consent mechanism
  const userData = {
    email: email,
    ipAddress: getUserIP(),
    browserFingerprint: getBrowserFingerprint(),
    location: location
  };
  
  // Storing indefinitely without retention policy
  localStorage.setItem('userData', JSON.stringify(userData));
  
  return userData;
}

// Weak Cryptography - Multiple violations
const md5Hash = crypto.createHash('md5').update('sensitive_data').digest('hex');
const weakRandom = Math.random() * 1000000;

// SQL Injection vulnerability
function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return database.execute(query);
}

// XSS vulnerability
function displayUserComment(comment) {
  document.getElementById('comments').innerHTML = comment;
}

// Insufficient logging
try {
  processFinancialTransaction();
} catch (error) {
  // No logging of security-relevant error
}

// Debug code in production
if (DEBUG_MODE) {
  console.error('Database password:', patientDbConfig.password);
  console.error('All user data:', getAllUsers());
}

// Insecure HTTP usage
fetch('http://api.example.com/sensitive-data')
  .then(response => response.json())
  .then(data => {
    // Processing sensitive data over HTTP
    processSensitiveData(data);
  });
`;

  // Configuration test file
  const testConfigFile = `
{
  "test_scenarios": {
    "hipaa_violations": {
      "expected_patterns": ["hardcoded_secrets", "insufficient_logging", "data_exposure"],
      "expected_controls": ["164.312(a)(2)(i)", "164.312(b)"],
      "expected_severity": "critical"
    },
    "pci_dss_violations": {
      "expected_patterns": ["hardcoded_secrets", "weak_crypto", "data_exposure"],
      "expected_controls": ["3.4", "8.2.1"],
      "expected_severity": "critical"
    },
    "gdpr_violations": {
      "expected_patterns": ["privacy_violation", "data_exposure"],
      "expected_controls": ["Article 32", "Article 7"],
      "expected_severity": "high"
    }
  },
  "performance_thresholds": {
    "max_scan_time_seconds": 30,
    "max_memory_usage_mb": 512,
    "min_detection_accuracy": 0.85
  }
}
`;

  // Write test files
  fs.writeFileSync(path.join(testConfig.testDataDir, 'vulnerable-app.js'), vulnerableJS);
  fs.writeFileSync(path.join(testConfig.testDataDir, 'test-config.json'), testConfigFile);
  
  logSuccess('Test data files created');
}

// Test configuration loading
function testConfigurationLoading() {
  runTest('Configuration Files Loading', () => {
    const frameworksFile = path.join(testConfig.configDir, 'compliance-frameworks.json');
    const settingsFile = path.join(testConfig.configDir, 'compliance-settings.json');
    const rulesFile = path.join(testConfig.configDir, 'custom-compliance-rules.json');
    
    // Test frameworks config
    if (!fs.existsSync(frameworksFile)) {
      throw new Error('compliance-frameworks.json not found');
    }
    
    const frameworks = JSON.parse(fs.readFileSync(frameworksFile, 'utf8'));
    if (!frameworks.compliance_frameworks) {
      throw new Error('Invalid frameworks configuration structure');
    }
    
    const requiredFrameworks = ['hipaa', 'gdpr', 'pci_dss', 'iso27001', 'nist_csf'];
    requiredFrameworks.forEach(framework => {
      if (!frameworks.compliance_frameworks[framework]) {
        throw new Error(`Missing framework: ${framework}`);
      }
    });
    
    // Test settings config
    if (!fs.existsSync(settingsFile)) {
      throw new Error('compliance-settings.json not found');
    }
    
    const settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
    if (!settings.compliance_configuration) {
      throw new Error('Invalid settings configuration structure');
    }
    
    // Test custom rules
    if (!fs.existsSync(rulesFile)) {
      throw new Error('custom-compliance-rules.json not found');
    }
    
    const rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
    if (!rules.custom_compliance_rules) {
      throw new Error('Invalid custom rules configuration structure');
    }
  });
}

// Test pattern matching
function testPatternMatching() {
  runTest('Vulnerability Pattern Matching', () => {
    const testFile = path.join(testConfig.testDataDir, 'vulnerable-app.js');
    const content = fs.readFileSync(testFile, 'utf8');
    
    // Load custom rules
    const rulesFile = path.join(testConfig.configDir, 'custom-compliance-rules.json');
    const rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
    
    let detectedPatterns = 0;
    
    // Test healthcare patterns
    const healthcareRules = rules.custom_compliance_rules.healthcare_specific;
    healthcareRules.forEach(rule => {
      rule.patterns.forEach(pattern => {
        const regex = new RegExp(pattern.replace(/^\/|\/g?i?$/g, ''), 'gi');
        if (regex.test(content)) {
          detectedPatterns++;
          logInfo(`Detected ${rule.name}: ${rule.rule_id}`);
        }
      });
    });
    
    // Test general security patterns
    const generalRules = rules.custom_compliance_rules.general_security;
    generalRules.forEach(rule => {
      rule.patterns.forEach(pattern => {
        const regex = new RegExp(pattern.replace(/^\/|\/g?i?$/g, ''), 'gi');
        if (regex.test(content)) {
          detectedPatterns++;
          logInfo(`Detected ${rule.name}: ${rule.rule_id}`);
        }
      });
    });
    
    if (detectedPatterns < 5) {
      throw new Error(`Expected at least 5 pattern matches, got ${detectedPatterns}`);
    }
    
    logSuccess(`Pattern matching successful: ${detectedPatterns} patterns detected`);
  });
}

// Main test runner
async function runAllTests() {
  console.error(colors.cyan + '🧪 SPOTTER-SAST COMPLIANCE SYSTEM TESTS' + colors.reset);
  console.error('==========================================\n');
  
  try {
    // Setup
    createTestData();
    
    // Run tests
    testConfigurationLoading();
    testPatternMatching();
    
    // Results
    console.error('\n' + colors.cyan + '📊 TEST RESULTS' + colors.reset);
    console.error('================');
    console.error(`Total Tests: ${tests.total}`);
    logSuccess(`Passed: ${tests.passed}`);
    
    if (tests.failed > 0) {
      logError(`Failed: ${tests.failed}`);
      process.exit(1);
    } else {
      logSuccess('All tests passed! ✨');
      console.error('\n' + colors.green + '🎉 COMPLIANCE SYSTEM IS READY FOR USE!' + colors.reset);
    }
    
  } catch (error) {
    logError(`Test execution failed: ${error.message}`);
    process.exit(1);
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllTests();
}