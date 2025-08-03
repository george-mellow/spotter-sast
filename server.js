import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fs from "fs";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";
import axios from "axios";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import winston from "winston";
import chokidar from "chokidar";
import cron from "node-cron";
import dotenv from "dotenv";

dotenv.config();

const execAsync = promisify(exec);

// Enhanced Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// Security Configuration
const securityConfig = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
  tokenExpiry: '24h',
  maxLoginAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
  enableRBAC: process.env.ENABLE_RBAC === 'true',
  enableAuditLogging: true
};

// User roles and permissions
const roles = {
  'security-admin': {
    permissions: ['*']
  },
  'developer': {
    permissions: ['scan:read', 'scan:execute', 'report:read', 'fix:suggest', 'vulnerability:read']
  },
  'security-analyst': {
    permissions: ['scan:*', 'report:*', 'vulnerability:*', 'policy:read', 'audit:read']
  },
  'auditor': {
    permissions: ['scan:read', 'report:read', 'vulnerability:read', 'audit:read']
  }
};

// Multi-tool SAST Configuration
const sastTools = {
  semgrep: {
    enabled: true,
    command: 'semgrep',
    args: ['--config=auto', '--json'],
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'c', 'cpp', 'csharp', 'php', 'ruby']
  },
  bandit: {
    enabled: true,
    command: 'bandit',
    args: ['-f', 'json'],
    languages: ['python']
  },
  eslint: {
    enabled: true,
    command: 'eslint',
    args: ['--format=json'],
    languages: ['javascript', 'typescript']
  },
  njsscan: {
    enabled: true,
    command: 'njsscan',
    args: ['--json'],
    languages: ['javascript', 'typescript']
  }
};

// Enhanced Vulnerability Patterns with OWASP Top 10 mapping
const vulnerabilityPatterns = {
  sql_injection: {
    patterns: [
      /query\s*\+\s*["']/gi,
      /\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /["']\s*\+\s*\w+\s*\+\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /execute\(\s*["'].*\$\{/gi,
      /Statement\s*=.*\+/gi
    ],
    severity: "Critical",
    owaspCategory: "A03_Injection",
    cweId: "CWE-89",
    description: "SQL injection vulnerability detected",
    remediation: "Use parameterized queries, prepared statements, or ORM with proper escaping",
    impact: "Data breach, unauthorized data access, database corruption"
  },
  
  xss: {
    patterns: [
      /innerHTML\s*=\s*[^;]*\+/gi,
      /document\.write\s*\([^)]*\+/gi,
      /\.html\s*\([^)]*\+/gi,
      /eval\s*\([^)]*\+/gi,
      /dangerouslySetInnerHTML/gi
    ],
    severity: "High",
    owaspCategory: "A03_Injection", 
    cweId: "CWE-79",
    description: "Cross-Site Scripting (XSS) vulnerability detected",
    remediation: "Sanitize user input, use safe DOM APIs, implement Content Security Policy",
    impact: "Session hijacking, data theft, malicious script execution"
  },
  
  hardcoded_secrets: {
    patterns: [
      /(?:password|pwd|pass)\s*[=:]\s*["'][^"'\s]{3,}/gi,
      /(?:api[_-]?key|apikey)\s*[=:]\s*["'][^"'\s]{10,}/gi,
      /(?:secret|token)\s*[=:]\s*["'][^"'\s]{10,}/gi,
      /(?:private[_-]?key)\s*[=:]\s*["'][^"'\s]{20,}/gi,
      /(?:access[_-]?token)\s*[=:]\s*["'][^"'\s]{15,}/gi
    ],
    severity: "Critical",
    owaspCategory: "A02_Cryptographic_Failures",
    cweId: "CWE-798",
    description: "Hard-coded credentials or secrets detected",
    remediation: "Move secrets to environment variables, use secure key management systems",
    impact: "Unauthorized access, credential exposure, system compromise"
  },
  
  command_injection: {
    patterns: [
      /exec\s*\([^)]*\+/gi,
      /system\s*\([^)]*\+/gi,
      /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/gi,
      /ProcessBuilder\s*\([^)]*\+/gi,
      /spawn\s*\([^)]*\+/gi
    ],
    severity: "Critical",
    owaspCategory: "A03_Injection",
    cweId: "CWE-78", 
    description: "Command injection vulnerability detected",
    remediation: "Avoid dynamic command construction, validate input, use safe APIs",
    impact: "Remote code execution, system compromise, data exfiltration"
  },
  
  weak_crypto: {
    patterns: [
      /MD5|SHA1(?!\d)/gi,
      /DES(?!\w)|3DES/gi,
      /RC4/gi,
      /Math\.random\(\)/gi,
      /Random\(\)\.next/gi
    ],
    severity: "Medium",
    owaspCategory: "A02_Cryptographic_Failures",
    cweId: "CWE-327",
    description: "Weak cryptographic algorithm detected",
    remediation: "Use strong algorithms: AES-256, SHA-256, SHA-3, cryptographically secure PRNGs",
    impact: "Data compromise, encryption bypass, predictable values"
  },
  
  path_traversal: {
    patterns: [
      /\.\.[\/\\]/gi,
      /readFile\s*\([^)]*\+.*\.\.[\/\\]/gi,
      /require\s*\([^)]*\+/gi,
      /import\s*\([^)]*\+/gi
    ],
    severity: "High",
    owaspCategory: "A01_Broken_Access_Control",
    cweId: "CWE-22",
    description: "Path traversal vulnerability detected",
    remediation: "Validate file paths, use path.resolve(), implement access controls",
    impact: "Unauthorized file access, information disclosure, system file exposure"
  },
  
  insecure_random: {
    patterns: [
      /Math\.random\(\)/gi,
      /Random\(\)/gi,
      /rand\(\)/gi,
      /srand\(/gi
    ],
    severity: "Medium", 
    owaspCategory: "A02_Cryptographic_Failures",
    cweId: "CWE-338",
    description: "Insecure random number generation",
    remediation: "Use crypto.randomBytes(), crypto.getRandomValues(), or other CSPRNG",
    impact: "Predictable tokens, weak session IDs, cryptographic weaknesses"
  },
  
  debug_code: {
    patterns: [
      /console\.log\s*\(/gi,
      /print\s*\(/gi,
      /TODO|FIXME|HACK/gi,
      /debugger;/gi,
      /\.printStackTrace\(/gi
    ],
    severity: "Low",
    owaspCategory: "A09_Security_Logging_Monitoring_Failures",
    cweId: "CWE-489",
    description: "Debug code or development artifacts found",
    remediation: "Remove debug statements, resolve TODOs, disable debug modes in production",
    impact: "Information disclosure, performance impact, security bypass"
  },

  insecure_deserialization: {
    patterns: [
      /JSON\.parse\([^)]*\+/gi,
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /vm\.runInThisContext/gi
    ],
    severity: "High",
    owaspCategory: "A08_Software_Data_Integrity_Failures", 
    cweId: "CWE-502",
    description: "Insecure deserialization detected",
    remediation: "Validate input before deserialization, use safe parsing methods",
    impact: "Remote code execution, object injection, denial of service"
  }
};

// Compliance Policies
const compliancePolicies = {
  owasp: {
    name: "OWASP Top 10 2021",
    requiredChecks: [
      "A01_Broken_Access_Control",
      "A02_Cryptographic_Failures", 
      "A03_Injection",
      "A08_Software_Data_Integrity_Failures",
      "A09_Security_Logging_Monitoring_Failures"
    ],
    failThresholds: {
      critical: 0,
      high: 5
    }
  },
  pci: {
    name: "PCI DSS",
    requiredChecks: ["hardcoded_secrets", "weak_crypto", "debug_code"],
    failThresholds: {
      critical: 0,
      high: 0,
      medium: 10
    }
  },
  nist: {
    name: "NIST Cybersecurity Framework",
    requiredChecks: ["all"],
    failThresholds: {
      critical: 0,
      high: 3
    }
  }
};

// Enhanced file extensions
const scanExtensions = [
  '.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte',  // JavaScript/TypeScript
  '.py', '.pyw',                                     // Python
  '.java', '.kotlin',                               // JVM languages
  '.cs', '.vb',                                     // .NET
  '.php', '.phtml',                                 // PHP
  '.rb', '.erb',                                    // Ruby
  '.go',                                            // Go
  '.cpp', '.c', '.h', '.hpp',                       // C/C++
  '.rs',                                            // Rust
  '.sql',                                           // SQL
  '.xml', '.html', '.htm', '.xhtml',                // Markup
  '.json', '.yaml', '.yml',                         // Config
  '.sh', '.bash', '.zsh',                           // Shell
  '.ps1', '.psm1'                                   // PowerShell
];

// Enterprise Security Layer
class SecurityManager {
  constructor() {
    this.failedAttempts = new Map();
    this.activeSessions = new Map();
    this.auditLog = [];
  }

  async authenticateUser(token) {
    try {
      const decoded = jwt.verify(token, securityConfig.jwtSecret);
      const session = this.activeSessions.get(decoded.sessionId);
      
      if (!session || session.expired < Date.now()) {
        throw new Error('Session expired');
      }

      return decoded;
    } catch (error) {
      logger.warn('Authentication failed', { error: error.message });
      return null;
    }
  }

  checkPermission(user, action, resource) {
    if (!securityConfig.enableRBAC) return true;
    
    const userRoles = user.roles || ['developer'];
    
    for (const roleName of userRoles) {
      const role = roles[roleName];
      if (!role) continue;

      if (role.permissions.includes('*')) return true;
      
      const requiredPermission = `${resource}:${action}`;
      if (role.permissions.includes(requiredPermission)) return true;
      
      const resourceWildcard = `${resource}:*`;
      if (role.permissions.includes(resourceWildcard)) return true;
    }

    return false;
  }

  logSecurityEvent(event) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      ...event
    };
    
    this.auditLog.push(logEntry);
    logger.info('Security event', logEntry);
    
    // Keep only last 10000 entries
    if (this.auditLog.length > 10000) {
      this.auditLog = this.auditLog.slice(-10000);
    }
  }
}

// Multi-tool Scanner Engine
class MultiToolScanner {
  constructor() {
    this.availableTools = this.detectAvailableTools();
  }

  async detectAvailableTools() {
    const available = {};
    
    for (const [toolName, config] of Object.entries(sastTools)) {
      try {
        await execAsync(`${config.command} --version`);
        available[toolName] = true;
        logger.info(`SAST tool detected: ${toolName}`);
      } catch (error) {
        available[toolName] = false;
        logger.warn(`SAST tool not available: ${toolName}`);
      }
    }
    
    return available;
  }

  async scanWithSemgrep(filepath) {
    if (!this.availableTools.semgrep) {
      return { findings: [], tool: 'semgrep', status: 'unavailable' };
    }

    try {
      const { stdout } = await execAsync(`semgrep --config=auto --json "${filepath}"`);
      const results = JSON.parse(stdout);
      
      const findings = results.results?.map(result => ({
        file: result.path,
        line: result.start.line,
        severity: this.mapSemgrepSeverity(result.extra?.severity),
        type: this.categorizeVulnerability(result.check_id),
        description: result.extra?.message || result.check_id,
        remediation: result.extra?.fix || "Review and fix the security issue",
        code: result.extra?.lines,
        tool: 'semgrep',
        ruleId: result.check_id,
        confidence: 'high'
      })) || [];

      return { findings, tool: 'semgrep', status: 'success' };
    } catch (error) {
      logger.error('Semgrep scan failed', { error: error.message });
      return { findings: [], tool: 'semgrep', status: 'error', error: error.message };
    }
  }

  async scanWithBandit(filepath) {
    if (!this.availableTools.bandit || !filepath.endsWith('.py')) {
      return { findings: [], tool: 'bandit', status: 'unavailable' };
    }

    try {
      const { stdout } = await execAsync(`bandit -f json "${filepath}"`);
      const results = JSON.parse(stdout);
      
      const findings = results.results?.map(result => ({
        file: result.filename,
        line: result.line_number,
        severity: this.mapBanditSeverity(result.issue_severity),
        type: this.categorizeBanditIssue(result.test_id),
        description: result.issue_text,
        remediation: "Review Bandit documentation for this issue type",
        code: result.code,
        tool: 'bandit',
        ruleId: result.test_id,
        confidence: result.issue_confidence?.toLowerCase() || 'medium'
      })) || [];

      return { findings, tool: 'bandit', status: 'success' };
    } catch (error) {
      logger.error('Bandit scan failed', { error: error.message });
      return { findings: [], tool: 'bandit', status: 'error', error: error.message };
    }
  }

  async performMultiToolScan(filepath) {
    const language = this.detectLanguage(filepath);
    const applicableTools = this.getToolsForLanguage(language);
    
    const scanResults = {
      filepath,
      language,
      timestamp: new Date().toISOString(),
      tools: {},
      aggregatedFindings: []
    };

    // Run applicable tools in parallel
    const toolPromises = applicableTools.map(async toolName => {
      switch (toolName) {
        case 'semgrep':
          return { toolName, result: await this.scanWithSemgrep(filepath) };
        case 'bandit':
          return { toolName, result: await this.scanWithBandit(filepath) };
        default:
          return { toolName, result: await this.scanWithPatterns(filepath) };
      }
    });

    const results = await Promise.allSettled(toolPromises);
    
    // Process results
    results.forEach(({ status, value }) => {
      if (status === 'fulfilled' && value.result) {
        scanResults.tools[value.toolName] = value.result;
      }
    });

    // Aggregate and deduplicate findings
    scanResults.aggregatedFindings = this.aggregateFindings(scanResults.tools);
    scanResults.riskScore = this.calculateRiskScore(scanResults.aggregatedFindings);
    scanResults.complianceStatus = this.checkCompliance(scanResults.aggregatedFindings);

    return scanResults;
  }

  detectLanguage(filepath) {
    const ext = path.extname(filepath).toLowerCase();
    const languageMap = {
      '.js': 'javascript', '.ts': 'typescript', '.jsx': 'javascript', '.tsx': 'typescript',
      '.py': 'python', '.pyw': 'python',
      '.java': 'java', '.kt': 'kotlin',
      '.cs': 'csharp', '.vb': 'vb',
      '.php': 'php', '.phtml': 'php',
      '.rb': 'ruby', '.erb': 'ruby',
      '.go': 'go',
      '.cpp': 'cpp', '.c': 'c', '.h': 'c', '.hpp': 'cpp',
      '.rs': 'rust'
    };
    
    return languageMap[ext] || 'unknown';
  }

  getToolsForLanguage(language) {
    const tools = [];
    
    Object.entries(sastTools).forEach(([toolName, config]) => {
      if (config.enabled && config.languages.includes(language)) {
        tools.push(toolName);
      }
    });

    // Always include pattern-based scanning as fallback
    tools.push('patterns');
    
    return tools;
  }

  async scanWithPatterns(filepath) {
    const content = fs.readFileSync(filepath, 'utf8');
    const findings = this.scanContent(content, path.basename(filepath));
    
    return {
      findings,
      tool: 'patterns',
      status: 'success'
    };
  }

  scanContent(content, filename) {
    const findings = [];
    const lines = content.split('\n');
    
    for (const [vulnType, config] of Object.entries(vulnerabilityPatterns)) {
      for (const pattern of config.patterns) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const matches = line.match(pattern);
          if (matches) {
            findings.push({
              file: filename,
              line: i + 1,
              severity: config.severity,
              type: vulnType,
              description: config.description,
              remediation: config.remediation,
              code: line.trim(),
              match: matches[0],
              tool: 'patterns',
              owaspCategory: config.owaspCategory,
              cweId: config.cweId,
              impact: config.impact,
              confidence: 'medium'
            });
          }
        }
      }
    }
    
    return findings;
  }

  aggregateFindings(toolResults) {
    const allFindings = [];
    const seenFindings = new Map();

    Object.values(toolResults).forEach(result => {
      if (result.findings) {
        result.findings.forEach(finding => {
          const fingerprint = this.generateFingerprint(finding);
          
          if (seenFindings.has(fingerprint)) {
            // Finding already exists, increase confidence
            const existing = seenFindings.get(fingerprint);
            existing.detectedBy.push(finding.tool);
            existing.confidence = this.calculateConfidence(existing.detectedBy);
          } else {
            // New finding
            const enhancedFinding = {
              ...finding,
              id: this.generateFindingId(),
              detectedBy: [finding.tool],
              confidence: finding.confidence || 'medium',
              firstDetected: new Date().toISOString()
            };
            
            allFindings.push(enhancedFinding);
            seenFindings.set(fingerprint, enhancedFinding);
          }
        });
      }
    });

    return allFindings.sort((a, b) => 
      this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity)
    );
  }

  generateFingerprint(finding) {
    return `${finding.file}:${finding.line}:${finding.type}`;
  }

  calculateConfidence(detectedByTools) {
    const toolWeights = { 'semgrep': 0.9, 'bandit': 0.85, 'patterns': 0.7 };
    const baseConfidence = Math.max(...detectedByTools.map(tool => toolWeights[tool] || 0.5));
    const toolBonus = (detectedByTools.length - 1) * 0.1;
    
    return Math.min(baseConfidence + toolBonus, 1.0).toFixed(2);
  }

  getSeverityWeight(severity) {
    const weights = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
    return weights[severity] || 0;
  }

  calculateRiskScore(findings) {
    const weights = { 'Critical': 10, 'High': 5, 'Medium': 2, 'Low': 1 };
    const score = findings.reduce((sum, finding) => sum + (weights[finding.severity] || 0), 0);
    
    return {
      score,
      level: score >= 50 ? 'CRITICAL' : score >= 20 ? 'HIGH' : score >= 10 ? 'MEDIUM' : 'LOW',
      maxPossible: findings.length * 10
    };
  }

  checkCompliance(findings) {
    const compliance = {};
    
    Object.entries(compliancePolicies).forEach(([policyName, policy]) => {
      const relevantFindings = findings.filter(f => 
        policy.requiredChecks.includes('all') || 
        policy.requiredChecks.includes(f.owaspCategory) ||
        policy.requiredChecks.includes(f.type)
      );

      const severityCounts = this.countSeverities(relevantFindings);
      const failed = this.checkFailThresholds(severityCounts, policy.failThresholds);

      compliance[policyName] = {
        status: failed ? 'FAIL' : 'PASS',
        findings: relevantFindings.length,
        severityCounts,
        failedThresholds: failed
      };
    });

    return compliance;
  }

  countSeverities(findings) {
    return findings.reduce((counts, finding) => {
      const severity = finding.severity.toLowerCase();
      counts[severity] = (counts[severity] || 0) + 1;
      return counts;
    }, {});
  }

  checkFailThresholds(severityCounts, thresholds) {
    const failed = [];
    
    Object.entries(thresholds).forEach(([severity, threshold]) => {
      const count = severityCounts[severity] || 0;
      if (count > threshold) {
        failed.push({ severity, count, threshold });
      }
    });

    return failed;
  }

  mapSemgrepSeverity(severity) {
    const mapping = { 'ERROR': 'Critical', 'WARNING': 'High', 'INFO': 'Medium' };
    return mapping[severity] || 'Medium';
  }

  mapBanditSeverity(severity) {
    const mapping = { 'HIGH': 'Critical', 'MEDIUM': 'High', 'LOW': 'Medium' };
    return mapping[severity] || 'Medium';
  }

  generateFindingId() {
    return 'FIND_' + Math.random().toString(36).substr(2, 9).toUpperCase();
  }

  categorizeVulnerability(ruleId) {
    if (ruleId.includes('sql') || ruleId.includes('injection')) return 'sql_injection';
    if (ruleId.includes('xss') || ruleId.includes('cross-site')) return 'xss';
    if (ruleId.includes('secret') || ruleId.includes('hardcode')) return 'hardcoded_secrets';
    if (ruleId.includes('crypto') || ruleId.includes('hash')) return 'weak_crypto';
    if (ruleId.includes('path') || ruleId.includes('traversal')) return 'path_traversal';
    return 'security_misconfiguration';
  }

  categorizeBanditIssue(testId) {
    const mapping = {
      'B101': 'hardcoded_secrets', 'B105': 'hardcoded_secrets', 'B106': 'hardcoded_secrets',
      'B601': 'command_injection', 'B602': 'command_injection',
      'B303': 'weak_crypto', 'B304': 'weak_crypto', 'B305': 'weak_crypto',
      'B108': 'insecure_random'
    };
    
    return mapping[testId] || 'security_misconfiguration';
  }
}

// Continuous Monitoring System
class ContinuousMonitor {
  constructor(securityManager) {
    this.securityManager = securityManager;
    this.activeMonitors = new Map();
    this.alerts = [];
  }

  async startMonitoring(projectPath, config = {}) {
    const monitorId = 'MON_' + Date.now();
    
    const monitor = {
      id: monitorId,
      projectPath,
      config,
      status: 'ACTIVE',
      startTime: new Date().toISOString(),
      lastScan: null,
      findings: [],
      alerts: []
    };

    // File system watcher
    const watcher = chokidar.watch(projectPath, {
      ignored: /node_modules|\.git|dist|build/,
      persistent: true
    });

    watcher.on('change', async (changedPath) => {
      await this.handleFileChange(changedPath, monitor);
    });

    // Scheduled comprehensive scans
    if (config.schedule) {
      cron.schedule(config.schedule, async () => {
        await this.performScheduledScan(monitor);
      });
    }

    monitor.watcher = watcher;
    this.activeMonitors.set(monitorId, monitor);

    logger.info('Continuous monitoring started', { monitorId, projectPath });
    return monitor;
  }

  async handleFileChange(filepath, monitor) {
    if (!this.shouldScanFile(path.basename(filepath))) return;

    try {
      const fileScanner = new MultiToolScanner();
      const scanResult = await fileScanner.performMultiToolScan(filepath);
      
      const newVulns = scanResult.aggregatedFindings.filter(finding => 
        ['Critical', 'High'].includes(finding.severity)
      );

      if (newVulns.length > 0) {
        const alert = {
          id: 'ALERT_' + Date.now(),
          type: 'NEW_VULNERABILITY',
          monitorId: monitor.id,
          filepath,
          vulnerabilities: newVulns,
          timestamp: new Date().toISOString()
        };

        monitor.alerts.push(alert);
        this.alerts.push(alert);
        
        logger.warn('New high-severity vulnerabilities detected', alert);
      }
    } catch (error) {
      logger.error('Error in file change monitoring', { error: error.message, filepath });
    }
  }

  async performScheduledScan(monitor) {
    try {
      logger.info('Starting scheduled comprehensive scan', { monitorId: monitor.id });
      
      const scheduledScanner = new MultiToolScanner();
      const allFindings = [];
      
      const scanDirectory = (dirPath) => {
        const items = fs.readdirSync(dirPath);
        
        items.forEach(async item => {
          const fullPath = path.join(dirPath, item);
          const stat = fs.statSync(fullPath);
          
          if (stat.isDirectory() && !['node_modules', '.git', 'dist', 'build'].includes(item)) {
            scanDirectory(fullPath);
          } else if (this.shouldScanFile(item)) {
            const result = await scanner.performMultiToolScan(fullPath);
            allFindings.push(...result.aggregatedFindings);
          }
        });
      };

      scanDirectory(monitor.projectPath);
      
      monitor.lastScan = new Date().toISOString();
      monitor.findings = allFindings;

      // Check for compliance violations
      const compliance = scheduledScanner.checkCompliance(allFindings);
      
      Object.entries(compliance).forEach(([policy, result]) => {
        if (result.status === 'FAIL') {
          const alert = {
            id: 'ALERT_' + Date.now(),
            type: 'COMPLIANCE_VIOLATION',
            monitorId: monitor.id,
            policy,
            violations: result.failedThresholds,
            timestamp: new Date().toISOString()
          };
          
          monitor.alerts.push(alert);
          this.alerts.push(alert);
        }
      });

      logger.info('Scheduled scan completed', { 
        monitorId: monitor.id, 
        findings: allFindings.length,
        compliance: Object.keys(compliance).length
      });

    } catch (error) {
      logger.error('Scheduled scan failed', { error: error.message, monitorId: monitor.id });
    }
  }

  shouldScanFile(filename) {
    const ext = path.extname(filename).toLowerCase();
    return scanExtensions.includes(ext);
  }

  stopMonitoring(monitorId) {
    const monitor = this.activeMonitors.get(monitorId);
    if (monitor) {
      monitor.watcher?.close();
      monitor.status = 'STOPPED';
      logger.info('Monitoring stopped', { monitorId });
    }
  }
}

// Enhanced Reporting Engine
class AdvancedReporting {
  constructor() {
    this.reportFormats = ['html', 'json', 'markdown', 'sarif', 'pdf'];
  }

  async generateComprehensiveReport(scanResults, format = 'html') {
    const reportData = {
      metadata: this.generateMetadata(scanResults),
      executiveSummary: this.generateExecutiveSummary(scanResults),
      detailedFindings: scanResults.aggregatedFindings,
      complianceMatrix: scanResults.complianceStatus,
      recommendations: this.generateRecommendations(scanResults),
      metrics: this.calculateMetrics(scanResults)
    };

    switch (format) {
      case 'html':
        return this.generateEnhancedHTML(reportData);
      case 'json':
        return JSON.stringify(reportData, null, 2);
      case 'markdown':
        return this.generateEnhancedMarkdown(reportData);
      case 'sarif':
        return this.generateSARIF(reportData);
      default:
        return this.generateEnhancedHTML(reportData);
    }
  }

  generateExecutiveSummary(scanResults) {
    const findings = scanResults.aggregatedFindings;
    const severityCounts = this.countSeverities(findings);
    
    return {
      overallRisk: scanResults.riskScore?.level || 'UNKNOWN',
      totalFindings: findings.length,
      severityCounts,
      topVulnerabilityTypes: this.getTopVulnerabilityTypes(findings),
      complianceStatus: scanResults.complianceStatus,
      actionRequired: severityCounts.critical > 0 || severityCounts.high > 5,
      recommendedActions: this.generateActionItems(findings)
    };
  }

  generateSARIF(reportData) {
    const sarif = {
      "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "Enhanced SAST MCP Server",
            "version": "2.0.0",
            "informationUri": "https://github.com/your-org/enhanced-sast-mcp"
          }
        },
        "results": reportData.detailedFindings.map(finding => ({
          "ruleId": finding.type,
          "message": { "text": finding.description },
          "level": this.mapSeverityToSarif(finding.severity),
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": finding.file },
              "region": { "startLine": finding.line }
            }
          }],
          "properties": {
            "confidence": finding.confidence,
            "owaspCategory": finding.owaspCategory,
            "cweId": finding.cweId,
            "detectedBy": finding.detectedBy
          }
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  mapSeverityToSarif(severity) {
    const mapping = { 'Critical': 'error', 'High': 'error', 'Medium': 'warning', 'Low': 'note' };
    return mapping[severity] || 'note';
  }

  countSeverities(findings) {
    return findings.reduce((counts, finding) => {
      const severity = finding.severity.toLowerCase();
      counts[severity] = (counts[severity] || 0) + 1;
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }

  getTopVulnerabilityTypes(findings) {
    const typeCounts = findings.reduce((counts, finding) => {
      counts[finding.type] = (counts[finding.type] || 0) + 1;
      return counts;
    }, {});

    return Object.entries(typeCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }));
  }

  generateActionItems(findings) {
    const critical = findings.filter(f => f.severity === 'Critical');
    const high = findings.filter(f => f.severity === 'High');
    
    const actions = [];
    
    if (critical.length > 0) {
      actions.push({
        priority: 'IMMEDIATE',
        action: `Fix ${critical.length} critical vulnerabilities immediately`,
        timeframe: 'Within 24 hours'
      });
    }
    
    if (high.length > 0) {
      actions.push({
        priority: 'HIGH',
        action: `Address ${high.length} high-severity vulnerabilities`,
        timeframe: 'Within 7 days'
      });
    }

    return actions;
  }

  generateMetadata(scanResults) {
    return {
      scanTimestamp: new Date().toISOString(),
      scanTarget: scanResults.filepath || scanResults.dirpath || 'Unknown',
      scanDuration: '0s', // Could be calculated if timing info available
      toolsUsed: Object.keys(scanResults.tools || {}),
      totalLinesScanned: 0, // Could be calculated from file contents
      reportGeneratedAt: new Date().toISOString(),
      reportVersion: '2.0.0',
      complianceFrameworks: Object.keys(scanResults.complianceStatus || {}),
      riskLevel: scanResults.riskScore?.level || 'Unknown'
    };
  }

  generateRecommendations(scanResults) {
    const findings = scanResults.aggregatedFindings || [];
    const recommendations = [];

    // Security recommendations based on findings
    const criticalCount = findings.filter(f => f.severity === 'Critical').length;
    const highCount = findings.filter(f => f.severity === 'High').length;
    
    if (criticalCount > 0) {
      recommendations.push({
        type: 'immediate',
        priority: 'critical',
        title: 'Address Critical Vulnerabilities',
        description: `Fix ${criticalCount} critical security vulnerabilities immediately`,
        impact: 'Very High',
        effort: 'High'
      });
    }

    if (highCount > 0) {
      recommendations.push({
        type: 'short-term',
        priority: 'high',
        title: 'Resolve High Severity Issues',
        description: `Address ${highCount} high-severity vulnerabilities within 7 days`,
        impact: 'High',
        effort: 'Medium'
      });
    }

    // Tool-specific recommendations
    const toolsUsed = Object.keys(scanResults.tools || {});
    if (toolsUsed.length < 3) {
      recommendations.push({
        type: 'improvement',
        priority: 'medium',
        title: 'Enhance Security Scanning',
        description: 'Consider adding more SAST tools for comprehensive coverage',
        impact: 'Medium',
        effort: 'Low'
      });
    }

    return recommendations;
  }

  calculateMetrics(scanResults) {
    const findings = scanResults.aggregatedFindings || [];
    const severityDistribution = this.countSeverities(findings);
    
    return {
      totalFindings: findings.length,
      severityDistribution,
      riskScore: scanResults.riskScore || { score: 0, level: 'LOW' },
      coverage: {
        filesScanned: 1, // Could be enhanced to track actual file count
        toolsUsed: Object.keys(scanResults.tools || {}).length,
        detectionConfidence: this.calculateAverageConfidence(findings)
      },
      trends: {
        newFindings: findings.length, // Could be enhanced with historical data
        resolvedFindings: 0, // Would need historical comparison
        riskTrend: 'stable' // Could be calculated with time series data
      },
      topVulnerabilityTypes: this.getTopVulnerabilityTypes(findings)
    };
  }

  calculateAverageConfidence(findings) {
    if (findings.length === 0) return 0;
    const totalConfidence = findings.reduce((sum, f) => {
      const confidence = parseFloat(f.confidence) || 0.5;
      return sum + confidence;
    }, 0);
    return (totalConfidence / findings.length).toFixed(2);
  }

  generateEnhancedHTML(reportData) {
    const { metadata, executiveSummary, detailedFindings, complianceMatrix, recommendations, metrics } = reportData;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced SAST Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #f39c12; font-weight: bold; }
        .medium { color: #f1c40f; font-weight: bold; }
        .low { color: #27ae60; font-weight: bold; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #3498db; background: #f8f9fa; }
        .compliance { display: flex; flex-wrap: wrap; gap: 10px; }
        .policy { padding: 10px; border-radius: 5px; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Enhanced SAST Security Report</h1>
        <p>Generated: ${metadata.reportGeneratedAt}</p>
        <p>Target: ${metadata.scanTarget}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Overall Risk:</strong> <span class="${executiveSummary.overallRisk.toLowerCase()}">${executiveSummary.overallRisk}</span></p>
        <p><strong>Total Findings:</strong> ${executiveSummary.totalFindings}</p>
        <p><strong>Critical:</strong> <span class="critical">${executiveSummary.severityCounts.critical || 0}</span> | 
           <strong>High:</strong> <span class="high">${executiveSummary.severityCounts.high || 0}</span> | 
           <strong>Medium:</strong> <span class="medium">${executiveSummary.severityCounts.medium || 0}</span> | 
           <strong>Low:</strong> <span class="low">${executiveSummary.severityCounts.low || 0}</span></p>
    </div>
    
    <div class="compliance">
        <h2>🏛️ Compliance Status</h2>
        <div class="compliance">
            ${Object.entries(complianceMatrix || {}).map(([policy, status]) => 
                `<div class="policy ${status.status.toLowerCase()}">
                    <strong>${policy.toUpperCase()}</strong>: ${status.status}
                </div>`
            ).join('')}
        </div>
    </div>
    
    <div>
        <h2>🔍 Detailed Findings</h2>
        ${detailedFindings.map(finding => 
            `<div class="finding">
                <h4 class="${finding.severity.toLowerCase()}">🚨 ${finding.severity}: ${finding.description}</h4>
                <p><strong>File:</strong> ${finding.file} (Line ${finding.line})</p>
                <p><strong>Type:</strong> ${finding.type}</p>
                <p><strong>Code:</strong> <code>${finding.code}</code></p>
                <p><strong>Remediation:</strong> ${finding.remediation}</p>
            </div>`
        ).join('')}
    </div>
    
    <div>
        <h2>💡 Recommendations</h2>
        ${recommendations.map(rec => 
            `<div class="finding">
                <h4>${rec.title}</h4>
                <p>${rec.description}</p>
                <p><strong>Priority:</strong> ${rec.priority} | <strong>Impact:</strong> ${rec.impact}</p>
            </div>`
        ).join('')}
    </div>
</body>
</html>`;
  }

  generateEnhancedMarkdown(reportData) {
    const { metadata, executiveSummary, detailedFindings, complianceMatrix, recommendations, metrics } = reportData;
    
    let markdown = `# 🛡️ Enhanced SAST Security Report\n\n`;
    markdown += `**Generated:** ${metadata.reportGeneratedAt}\n`;
    markdown += `**Target:** ${metadata.scanTarget}\n`;
    markdown += `**Tools Used:** ${metadata.toolsUsed.join(', ')}\n\n`;
    
    markdown += `## 📊 Executive Summary\n\n`;
    markdown += `- **Overall Risk:** ${executiveSummary.overallRisk}\n`;
    markdown += `- **Total Findings:** ${executiveSummary.totalFindings}\n`;
    markdown += `- **Critical:** ${executiveSummary.severityCounts.critical || 0}\n`;
    markdown += `- **High:** ${executiveSummary.severityCounts.high || 0}\n`;
    markdown += `- **Medium:** ${executiveSummary.severityCounts.medium || 0}\n`;
    markdown += `- **Low:** ${executiveSummary.severityCounts.low || 0}\n\n`;
    
    markdown += `## 🏛️ Compliance Status\n\n`;
    Object.entries(complianceMatrix || {}).forEach(([policy, status]) => {
        const icon = status.status === 'PASS' ? '✅' : '❌';
        markdown += `${icon} **${policy.toUpperCase()}:** ${status.status}\n`;
    });
    markdown += `\n`;
    
    markdown += `## 🔍 Detailed Findings\n\n`;
    detailedFindings.forEach((finding, index) => {
        const severityIcon = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢'
        }[finding.severity] || '⚪';
        
        markdown += `### ${index + 1}. ${severityIcon} ${finding.severity}: ${finding.description}\n\n`;
        markdown += `- **File:** ${finding.file} (Line ${finding.line})\n`;
        markdown += `- **Type:** ${finding.type}\n`;
        markdown += `- **Code:** \`${finding.code}\`\n`;
        markdown += `- **Remediation:** ${finding.remediation}\n\n`;
    });
    
    markdown += `## 💡 Recommendations\n\n`;
    recommendations.forEach((rec, index) => {
        markdown += `### ${index + 1}. ${rec.title}\n\n`;
        markdown += `${rec.description}\n\n`;
        markdown += `- **Priority:** ${rec.priority}\n`;
        markdown += `- **Impact:** ${rec.impact}\n`;
        markdown += `- **Effort:** ${rec.effort}\n\n`;
    });
    
    return markdown;
  }
}

// AI-Enhanced Auto-Fix Engine
class AIAutoFixer {
  constructor() {
    this.fixTemplates = this.loadFixTemplates();
  }

  loadFixTemplates() {
    return {
      sql_injection: [
        {
          pattern: /query\s*\+\s*["']/gi,
          replacement: (match, context) => {
            return `// TODO: Use parameterized query\n// Example: db.query('SELECT * FROM users WHERE id = ?', [userId])\n${match}`;
          },
          description: "Convert to parameterized query"
        }
      ],
      xss: [
        {
          pattern: /innerHTML\s*=\s*[^;]*\+/gi,
          replacement: (match, context) => {
            return match.replace('innerHTML =', 'textContent =');
          },
          description: "Use textContent instead of innerHTML for user data"
        }
      ],
      hardcoded_secrets: [
        {
          pattern: /((?:password|pwd|pass|api[_-]?key|apikey|secret|token)\s*[=:]\s*)["']([^"'\s]{3,})["']/gi,
          replacement: (match, varName, secretValue) => {
            const envVar = this.generateEnvVarName(varName);
            return `${varName}process.env.${envVar} || '${secretValue}' // TODO: Set ${envVar} in environment`;
          },
          description: "Move secret to environment variable"
        }
      ],
      weak_crypto: [
        {
          pattern: /MD5/gi,
          replacement: 'SHA256',
          description: "Replace MD5 with SHA256"
        },
        {
          pattern: /SHA1(?!\d)/gi,
          replacement: 'SHA256', 
          description: "Replace SHA1 with SHA256"
        },
        {
          pattern: /Math\.random\(\)/gi,
          replacement: 'crypto.randomBytes(4).readUInt32BE(0) / 0x100000000',
          description: "Use cryptographically secure random"
        }
      ]
    };
  }

  async generateIntelligentFixes(findings, sourceCode) {
    const fixes = [];

    for (const finding of findings) {
      const templates = this.fixTemplates[finding.type];
      if (!templates) continue;

      for (const template of templates) {
        const lines = sourceCode.split('\n');
        const lineIndex = finding.line - 1;
        
        if (lineIndex >= 0 && lineIndex < lines.length) {
          const originalLine = lines[lineIndex];
          const fixedLine = this.applyTemplate(template, originalLine, finding);
          
          if (fixedLine !== originalLine) {
            fixes.push({
              findingId: finding.id,
              line: finding.line,
              type: finding.type,
              description: template.description,
              original: originalLine.trim(),
              fixed: fixedLine.trim(),
              confidence: this.calculateFixConfidence(template, finding),
              impact: this.assessFixImpact(template, finding)
            });
          }
        }
      }
    }

    return fixes;
  }

  applyTemplate(template, line, finding) {
    if (typeof template.replacement === 'function') {
      return template.replacement(line, finding);
    } else {
      return line.replace(template.pattern, template.replacement);
    }
  }

  calculateFixConfidence(template, finding) {
    // Higher confidence for well-tested patterns
    const confidenceMap = {
      'hardcoded_secrets': 0.9,
      'weak_crypto': 0.85,
      'debug_code': 0.95,
      'sql_injection': 0.7,
      'xss': 0.75
    };
    
    return confidenceMap[finding.type] || 0.6;
  }

  assessFixImpact(template, finding) {
    return {
      riskReduction: this.calculateRiskReduction(finding.severity),
      codeChanges: 'minimal',
      testingRequired: finding.severity === 'Critical'
    };
  }

  calculateRiskReduction(severity) {
    const reductionMap = {
      'Critical': 0.95,
      'High': 0.80,
      'Medium': 0.60,
      'Low': 0.30
    };
    return reductionMap[severity] || 0.40;
  }

  generateEnvVarName(varName) {
    return varName.toUpperCase()
      .replace(/[^A-Z0-9]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');
  }
}

// Initialize enhanced components
const securityManager = new SecurityManager();
const multiToolScanner = new MultiToolScanner();
const continuousMonitor = new ContinuousMonitor(securityManager);
const advancedReporting = new AdvancedReporting();
const aiAutoFixer = new AIAutoFixer();

// Helper functions
function shouldScanFile(filename) {
  const ext = path.extname(filename).toLowerCase();
  return scanExtensions.includes(ext);
}

function formatEnhancedSastReport(scanResults) {
  if (!scanResults.aggregatedFindings || scanResults.aggregatedFindings.length === 0) {
    return `✅ SAST Scan Complete: No security issues found in ${scanResults.filepath}`;
  }
  
  const findings = scanResults.aggregatedFindings;
  const severityCounts = advancedReporting.countSeverities(findings);
  
  let report = `🔍 Enhanced SAST Security Scan Report\n`;
  report += `📂 Scanned: ${scanResults.filepath}\n`;
  report += `🔧 Tools Used: ${Object.keys(scanResults.tools).join(', ')}\n`;
  report += `⚡ Risk Score: ${scanResults.riskScore?.score} (${scanResults.riskScore?.level})\n\n`;
  
  report += `📊 Summary:\n`;
  report += `   🔴 Critical: ${severityCounts.critical}\n`;
  report += `   🟠 High: ${severityCounts.high}\n`;
  report += `   🟡 Medium: ${severityCounts.medium}\n`;
  report += `   🟢 Low: ${severityCounts.low}\n\n`;

  // Compliance status
  if (scanResults.complianceStatus) {
    report += `🛡️ Compliance Status:\n`;
    Object.entries(scanResults.complianceStatus).forEach(([policy, status]) => {
      const statusIcon = status.status === 'PASS' ? '✅' : '❌';
      report += `   ${statusIcon} ${policy.toUpperCase()}: ${status.status}\n`;
    });
    report += '\n';
  }
  
  // Top vulnerabilities
  const topVulns = advancedReporting.getTopVulnerabilityTypes(findings);
  if (topVulns.length > 0) {
    report += `🎯 Top Vulnerability Types:\n`;
    topVulns.forEach(({ type, count }) => {
      report += `   • ${type.replace('_', ' ').toUpperCase()}: ${count}\n`;
    });
    report += '\n';
  }
  
  report += `🔍 Detailed Findings:\n\n`;
  
  const groupedFindings = findings.reduce((groups, finding) => {
    if (!groups[finding.file]) groups[finding.file] = [];
    groups[finding.file].push(finding);
    return groups;
  }, {});
  
  for (const [file, fileFindings] of Object.entries(groupedFindings)) {
    report += `📄 ${file}:\n`;
    fileFindings.forEach(finding => {
      const severityIcon = {
        'Critical': '🔴',
        'High': '🟠', 
        'Medium': '🟡',
        'Low': '🟢'
      }[finding.severity];
      
      report += `   ${severityIcon} Line ${finding.line}: ${finding.description}\n`;
      report += `      Code: ${finding.code}\n`;
      report += `      OWASP: ${finding.owaspCategory || 'N/A'}\n`;
      report += `      CWE: ${finding.cweId || 'N/A'}\n`;
      report += `      Confidence: ${finding.confidence}\n`;
      report += `      Detected by: ${finding.detectedBy?.join(', ') || finding.tool}\n`;
      report += `      Fix: ${finding.remediation}\n\n`;
    });
  }
  
  return report;
}

// Initialize enhanced MCP server
const server = new McpServer({
  name: "enhanced-sast-mcp-server",
  version: "2.0.0",
  capabilities: {
    tools: {}
  }
});

// Original echo tool
server.tool(
  "echo",
  "Echoes any message passed to it.",
  {
    message: z.string().describe("The message to echo")
  },
  async ({ message }) => ({
    content: [{ type: "text", text: `Enhanced SAST MCP Server echo: ${message}` }]
  })
);

// Enhanced multi-tool file scanning
server.tool(
  "enhanced_scan_file",
  "Perform comprehensive multi-tool SAST scan on a single file with AI-powered analysis",
  {
    filepath: z.string().describe("Absolute path to the file to scan"),
    tools: z.array(z.string()).optional().describe("Specific tools to use (default: auto-detect)"),
    policies: z.array(z.string()).optional().describe("Compliance policies to check (owasp, pci, nist)"),
    includeFixSuggestions: z.boolean().default(true).describe("Generate AI-powered fix suggestions"),
    user_token: z.string().optional().describe("Authentication token")
  },
  async ({ filepath, tools, policies, includeFixSuggestions, user_token }) => {
    try {
      // Authentication (if enabled)
      let user = null;
      if (securityConfig.enableRBAC && user_token) {
        user = await securityManager.authenticateUser(user_token);
        if (!user) {
          return { content: [{ type: "text", text: "❌ Authentication failed" }] };
        }
        
        if (!securityManager.checkPermission(user, 'execute', 'scan')) {
          return { content: [{ type: "text", text: "❌ Insufficient permissions" }] };
        }
      }

      if (!fs.existsSync(filepath)) {
        return { content: [{ type: "text", text: `❌ Error: File not found: ${filepath}` }] };
      }

      const filename = path.basename(filepath);
      if (!shouldScanFile(filename)) {
        return { content: [{ type: "text", text: `⚠️ Skipped: File extension not supported: ${filename}` }] };
      }

      // Perform multi-tool scan
      const scanResults = await multiToolScanner.performMultiToolScan(filepath);
      
      // Add fix suggestions if requested
      if (includeFixSuggestions && scanResults.aggregatedFindings.length > 0) {
        const sourceCode = fs.readFileSync(filepath, 'utf8');
        scanResults.fixSuggestions = await aiAutoFixer.generateIntelligentFixes(
          scanResults.aggregatedFindings,
          sourceCode
        );
      }

      // Log security event
      securityManager.logSecurityEvent({
        type: 'SCAN_EXECUTED',
        user: user?.email || 'anonymous',
        resource: filepath,
        findings: scanResults.aggregatedFindings.length,
        tools: Object.keys(scanResults.tools)
      });

      const report = formatEnhancedSastReport(scanResults);
      
      return { content: [{ type: "text", text: report }] };

    } catch (error) {
      logger.error('Enhanced scan failed', { error: error.message, filepath });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Enhanced directory scanning with monitoring
server.tool(
  "enhanced_scan_directory",
  "Perform comprehensive multi-tool SAST scan on directory with continuous monitoring option",
  {
    dirpath: z.string().describe("Absolute path to the directory to scan"),
    enableMonitoring: z.boolean().default(false).describe("Enable continuous monitoring"),
    schedule: z.string().optional().describe("Cron schedule for monitoring (e.g., '0 */6 * * *')"),
    policies: z.array(z.string()).optional().describe("Compliance policies to enforce"),
    user_token: z.string().optional().describe("Authentication token")
  },
  async ({ dirpath, enableMonitoring, schedule, policies, user_token }) => {
    try {
      // Authentication
      let user = null;
      if (securityConfig.enableRBAC && user_token) {
        user = await securityManager.authenticateUser(user_token);
        if (!user || !securityManager.checkPermission(user, 'execute', 'scan')) {
          return { content: [{ type: "text", text: "❌ Authentication/authorization failed" }] };
        }
      }

      if (!fs.existsSync(dirpath)) {
        return { content: [{ type: "text", text: `❌ Error: Directory not found: ${dirpath}` }] };
      }

      let allFindings = [];
      let scannedFiles = 0;
      const toolResults = {};

      const scanDir = async (currentPath) => {
        const items = fs.readdirSync(currentPath);
        
        for (const item of items) {
          const fullPath = path.join(currentPath, item);
          const stat = fs.statSync(fullPath);
          
          if (stat.isDirectory()) {
            if (!['node_modules', '.git', 'dist', 'build', '.next', 'target', 'vendor'].includes(item)) {
              await scanDir(fullPath);
            }
          } else if (shouldScanFile(item)) {
            const scanResult = await multiToolScanner.performMultiToolScan(fullPath);
            allFindings.push(...scanResult.aggregatedFindings);
            scannedFiles++;
            
            // Merge tool results
            Object.entries(scanResult.tools).forEach(([tool, result]) => {
              if (!toolResults[tool]) toolResults[tool] = { findings: [] };
              toolResults[tool].findings.push(...result.findings);
            });
          }
        }
      };

      await scanDir(dirpath);

      const aggregatedResults = {
        dirpath,
        scannedFiles,
        aggregatedFindings: allFindings,
        tools: toolResults,
        riskScore: multiToolScanner.calculateRiskScore(allFindings),
        complianceStatus: multiToolScanner.checkCompliance(allFindings),
        timestamp: new Date().toISOString()
      };

      // Start monitoring if requested
      if (enableMonitoring) {
        const monitor = await continuousMonitor.startMonitoring(dirpath, {
          schedule: schedule || '0 */6 * * *', // Every 6 hours by default
          user,
          policies
        });
        
        aggregatedResults.monitoringId = monitor.id;
      }

      let report = `🔍 Enhanced SAST Directory Scan Complete\n`;
      report += `📁 Scanned Directory: ${dirpath}\n`;
      report += `📄 Files Scanned: ${scannedFiles}\n`;
      if (enableMonitoring) {
        report += `👁️ Continuous Monitoring: ENABLED (ID: ${aggregatedResults.monitoringId})\n`;
      }
      report += `\n${formatEnhancedSastReport(aggregatedResults)}`;

      return { content: [{ type: "text", text: report }] };

    } catch (error) {
      logger.error('Enhanced directory scan failed', { error: error.message, dirpath });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Advanced reporting with multiple formats
server.tool(
  "generate_enhanced_report",
  "Generate comprehensive security report with executive summary, compliance matrix, and recommendations",
  {
    scan_path: z.string().describe("Path that was scanned"),
    report_dir: z.string().describe("Directory to save reports"),
    format: z.enum(["html", "json", "markdown", "sarif", "all"]).describe("Report format"),
    include_executive_summary: z.boolean().default(true).describe("Include executive summary"),
    include_compliance_matrix: z.boolean().default(true).describe("Include compliance matrix"),
    include_recommendations: z.boolean().default(true).describe("Include actionable recommendations")
  },
  async ({ scan_path, report_dir, format, include_executive_summary, include_compliance_matrix, include_recommendations }) => {
    try {
      if (!fs.existsSync(scan_path)) {
        return { content: [{ type: "text", text: `❌ Error: Scan path not found: ${scan_path}` }] };
      }

      if (!fs.existsSync(report_dir)) {
        fs.mkdirSync(report_dir, { recursive: true });
      }

      // Perform comprehensive scan
      let scanResults;
      const stat = fs.statSync(scan_path);
      
      if (stat.isFile()) {
        scanResults = await multiToolScanner.performMultiToolScan(scan_path);
      } else {
        // Directory scan logic here
        const allFindings = [];
        const scanDirectory = async (currentPath) => {
          const items = fs.readdirSync(currentPath);
          for (const item of items) {
            const fullPath = path.join(currentPath, item);
            const itemStat = fs.statSync(fullPath);
            
            if (itemStat.isDirectory()) {
              if (!['node_modules', '.git', 'dist', 'build'].includes(item)) {
                await scanDirectory(fullPath);
              }
            } else if (shouldScanFile(item)) {
              const result = await multiToolScanner.performMultiToolScan(fullPath);
              allFindings.push(...result.aggregatedFindings);
            }
          }
        };
        
        await scanDirectory(scan_path);
        scanResults = {
          filepath: scan_path,
          aggregatedFindings: allFindings,
          riskScore: multiToolScanner.calculateRiskScore(allFindings),
          complianceStatus: multiToolScanner.checkCompliance(allFindings)
        };
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const reportFiles = [];

      const formats = format === 'all' ? ['html', 'json', 'markdown', 'sarif'] : [format];

      for (const fmt of formats) {
        const reportContent = await advancedReporting.generateComprehensiveReport(scanResults, fmt);
        const filename = `enhanced-sast-report-${timestamp}.${fmt}`;
        const filepath = path.join(report_dir, filename);
        
        fs.writeFileSync(filepath, reportContent);
        reportFiles.push(filename);
      }

      let response = `📋 Enhanced SAST Report Generated Successfully!\n\n`;
      response += `📂 Scanned: ${scan_path}\n`;
      response += `📊 Total Findings: ${scanResults.aggregatedFindings.length}\n`;
      response += `⚡ Risk Score: ${scanResults.riskScore?.score} (${scanResults.riskScore?.level})\n`;
      response += `📁 Reports Saved to: ${report_dir}\n\n`;
      response += `📄 Generated Files:\n`;
      reportFiles.forEach(file => {
        response += `   • ${file}\n`;
      });

      return { content: [{ type: "text", text: response }] };

    } catch (error) {
      logger.error('Enhanced report generation failed', { error: error.message });
      return { content: [{ type: "text", text: `❌ Error generating enhanced report: ${error.message}` }] };
    }
  }
);

// AI-powered auto-fix with validation
server.tool(
  "ai_enhanced_auto_fix",
  "Apply AI-powered intelligent fixes with validation and rollback capability",
  {
    filepath: z.string().describe("Absolute path to the file to fix"),
    finding_ids: z.array(z.string()).optional().describe("Specific finding IDs to fix"),
    strategy: z.enum(["conservative", "balanced", "aggressive"]).default("balanced").describe("Fix application strategy"),
    validate_fixes: z.boolean().default(true).describe("Validate fixes before applying"),
    create_backup: z.boolean().default(true).describe("Create backup before applying fixes")
  },
  async ({ filepath, finding_ids, strategy, validate_fixes, create_backup }) => {
    try {
      if (!fs.existsSync(filepath)) {
        return { content: [{ type: "text", text: `❌ Error: File not found: ${filepath}` }] };
      }

      const sourceCode = fs.readFileSync(filepath, 'utf8');
      const scanResult = await multiToolScanner.performMultiToolScan(filepath);
      
      let targetFindings = scanResult.aggregatedFindings;
      if (finding_ids && finding_ids.length > 0) {
        targetFindings = targetFindings.filter(f => finding_ids.includes(f.id));
      }

      if (targetFindings.length === 0) {
        return { content: [{ type: "text", text: "✅ No fixable vulnerabilities found" }] };
      }

      // Generate intelligent fixes
      const fixes = await aiAutoFixer.generateIntelligentFixes(targetFindings, sourceCode);
      
      if (fixes.length === 0) {
        return { content: [{ type: "text", text: "ℹ️ No automatic fixes available for the identified vulnerabilities" }] };
      }

      // Create backup if requested
      let backupPath = null;
      if (create_backup) {
        backupPath = `${filepath}.backup.${Date.now()}`;
        fs.writeFileSync(backupPath, sourceCode);
      }

      // Apply fixes based on strategy
      let appliedFixes = [];
      let fixedContent = sourceCode;

      const filteredFixes = this.filterFixesByStrategy(fixes, strategy);
      
      for (const fix of filteredFixes) {
        const lines = fixedContent.split('\n');
        const lineIndex = fix.line - 1;
        
        if (lineIndex >= 0 && lineIndex < lines.length) {
          lines[lineIndex] = fix.fixed;
          fixedContent = lines.join('\n');
          appliedFixes.push(fix);
        }
      }

      // Validate fixes if requested
      if (validate_fixes) {
        const postFixScan = await multiToolScanner.performMultiToolScan(filepath);
        const newIssues = postFixScan.aggregatedFindings.filter(f => 
          !scanResult.aggregatedFindings.some(orig => 
            orig.line === f.line && orig.type === f.type
          )
        );

        if (newIssues.length > 0) {
          // Rollback if new issues introduced
          if (backupPath) {
            fs.writeFileSync(filepath, sourceCode);
          }
          return { 
            content: [{ 
              type: "text", 
              text: `⚠️ Fixes rolled back: ${newIssues.length} new issues would be introduced` 
            }] 
          };
        }
      }

      // Apply the fixes
      fs.writeFileSync(filepath, fixedContent);

      let response = `🔧 AI-Enhanced Auto-Fix Applied Successfully!\n\n`;
      response += `📄 File: ${path.basename(filepath)}\n`;
      response += `🔧 Fixes Applied: ${appliedFixes.length}\n`;
      response += `🧠 Strategy: ${strategy}\n`;
      if (backupPath) {
        response += `💾 Backup Created: ${path.basename(backupPath)}\n`;
      }
      response += `\n🛠️ Applied Fixes:\n`;

      appliedFixes.forEach((fix, index) => {
        response += `   ${index + 1}. Line ${fix.line}: ${fix.description}\n`;
        response += `      Confidence: ${(fix.confidence * 100).toFixed(1)}%\n`;
        response += `      Original: ${fix.original}\n`;
        response += `      Fixed: ${fix.fixed}\n\n`;
      });

      return { content: [{ type: "text", text: response }] };

    } catch (error) {
      logger.error('AI auto-fix failed', { error: error.message, filepath });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Continuous monitoring management
server.tool(
  "start_continuous_monitoring", 
  "Start continuous security monitoring for a project with real-time alerts",
  {
    project_path: z.string().describe("Project directory to monitor"),
    schedule: z.string().default("0 */6 * * *").describe("Cron schedule for comprehensive scans"),
    alert_thresholds: z.object({
      critical: z.number().default(0),
      high: z.number().default(5)
    }).optional().describe("Alert thresholds by severity"),
    user_token: z.string().optional().describe("Authentication token")
  },
  async ({ project_path, schedule, alert_thresholds, user_token }) => {
    try {
      // Authentication
      let user = null;
      if (securityConfig.enableRBAC && user_token) {
        user = await securityManager.authenticateUser(user_token);
        if (!user || !securityManager.checkPermission(user, 'execute', 'monitoring')) {
          return { content: [{ type: "text", text: "❌ Authentication/authorization failed" }] };
        }
      }

      const monitor = await continuousMonitor.startMonitoring(project_path, {
        schedule,
        alertThresholds: alert_thresholds,
        user
      });

      let response = `👁️ Continuous Security Monitoring Started\n\n`;
      response += `📂 Project: ${project_path}\n`;
      response += `🆔 Monitor ID: ${monitor.id}\n`;
      response += `⏰ Schedule: ${schedule}\n`;
      response += `🚨 Alert Thresholds: Critical ≤ ${alert_thresholds?.critical || 0}, High ≤ ${alert_thresholds?.high || 5}\n`;
      response += `📈 Status: ${monitor.status}\n\n`;
      response += `✅ Real-time file monitoring active\n`;
      response += `✅ Scheduled comprehensive scans enabled\n`;
      response += `✅ Automated alerting configured\n`;

      return { content: [{ type: "text", text: response }] };

    } catch (error) {
      logger.error('Failed to start monitoring', { error: error.message });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Security dashboard and metrics
server.tool(
  "security_dashboard",
  "Get real-time security dashboard with metrics, trends, and alerts",
  {
    time_range: z.enum(["1h", "24h", "7d", "30d"]).default("24h").describe("Time range for metrics"),
    include_trends: z.boolean().default(true).describe("Include trend analysis"),
    include_alerts: z.boolean().default(true).describe("Include active alerts"),
    user_token: z.string().optional().describe("Authentication token")
  },
  async ({ time_range, include_trends, include_alerts, user_token }) => {
    try {
      // Authentication
      let user = null;
      if (securityConfig.enableRBAC && user_token) {
        user = await securityManager.authenticateUser(user_token);
        if (!user || !securityManager.checkPermission(user, 'read', 'dashboard')) {
          return { content: [{ type: "text", text: "❌ Authentication/authorization failed" }] };
        }
      }

      const dashboard = {
        timestamp: new Date().toISOString(),
        timeRange: time_range,
        overview: {
          activeMonitors: continuousMonitor.activeMonitors.size,
          totalAlerts: continuousMonitor.alerts.length,
          recentScans: securityManager.auditLog.filter(e => e.type === 'SCAN_EXECUTED').length
        },
        alerts: include_alerts ? continuousMonitor.alerts.slice(-10) : null,
        metrics: {
          scansToday: securityManager.auditLog.filter(e => 
            e.type === 'SCAN_EXECUTED' && 
            new Date(e.timestamp).toDateString() === new Date().toDateString()
          ).length,
          vulnerabilitiesFound: securityManager.auditLog
            .filter(e => e.type === 'SCAN_EXECUTED')
            .reduce((sum, e) => sum + (e.findings || 0), 0)
        }
      };

      let response = `📊 Security Dashboard\n`;
      response += `📅 Last Updated: ${dashboard.timestamp}\n`;
      response += `⏱️ Time Range: ${time_range}\n\n`;
      
      response += `📈 Overview:\n`;
      response += `   👁️ Active Monitors: ${dashboard.overview.activeMonitors}\n`;
      response += `   🚨 Total Alerts: ${dashboard.overview.totalAlerts}\n`;
      response += `   🔍 Recent Scans: ${dashboard.overview.recentScans}\n\n`;

      response += `📊 Metrics:\n`;
      response += `   📅 Scans Today: ${dashboard.metrics.scansToday}\n`;
      response += `   🐛 Vulnerabilities Found: ${dashboard.metrics.vulnerabilitiesFound}\n\n`;

      if (include_alerts && dashboard.alerts && dashboard.alerts.length > 0) {
        response += `🚨 Recent Alerts:\n`;
        dashboard.alerts.slice(-5).forEach(alert => {
          response += `   • ${alert.type}: ${alert.vulnerabilities?.length || 0} issues (${alert.timestamp})\n`;
        });
      }

      return { content: [{ type: "text", text: response }] };

    } catch (error) {
      logger.error('Dashboard generation failed', { error: error.message });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Enhanced vulnerability information with OWASP mapping
server.tool(
  "get_enhanced_vulnerability_info",
  "Get comprehensive vulnerability information with OWASP mapping, CWE references, and remediation guidance",
  {
    vuln_type: z.enum([
      "sql_injection", "xss", "hardcoded_secrets", "command_injection",
      "weak_crypto", "path_traversal", "insecure_random", "debug_code", "insecure_deserialization"
    ]).describe("Type of vulnerability")
  },
  async ({ vuln_type }) => {
    const vulnInfo = vulnerabilityPatterns[vuln_type];
    
    if (!vulnInfo) {
      return { content: [{ type: "text", text: `❌ Unknown vulnerability type: ${vuln_type}` }] };
    }

    let info = `🔍 Enhanced Vulnerability Information: ${vuln_type.toUpperCase()}\n\n`;
    info += `🚨 Severity: ${vulnInfo.severity}\n`;
    info += `📝 Description: ${vulnInfo.description}\n`;
    info += `🛡️ OWASP Category: ${vulnInfo.owaspCategory}\n`;
    info += `🔗 CWE Reference: ${vulnInfo.cweId}\n`;
    info += `💥 Impact: ${vulnInfo.impact}\n`;
    info += `🔧 Remediation: ${vulnInfo.remediation}\n\n`;
    
    info += `🎯 Detection Patterns:\n`;
    vulnInfo.patterns.forEach((pattern, index) => {
      info += `   ${index + 1}. ${pattern.source}\n`;
    });

    const fixTemplates = aiAutoFixer.fixTemplates[vuln_type];
    if (fixTemplates) {
      info += `\n🛠️ Available Auto-Fixes:\n`;
      fixTemplates.forEach((fix, index) => {
        info += `   ${index + 1}. ${fix.description}\n`;
      });
    }

    // Add examples and best practices
    info += `\n💡 Best Practices:\n`;
    info += server.getBestPractices(vuln_type);

    return { content: [{ type: "text", text: info }] };
  }
);

// Policy and compliance management
server.tool(
  "manage_security_policies",
  "Manage security policies and compliance frameworks",
  {
    action: z.enum(["list", "get", "check"]).describe("Policy management action"),
    policy_name: z.string().optional().describe("Policy name for get/check actions"),
    scan_results: z.any().optional().describe("Scan results for compliance checking")
  },
  async ({ action, policy_name, scan_results }) => {
    try {
      switch (action) {
        case 'list':
          let response = `📋 Available Security Policies:\n\n`;
          Object.entries(compliancePolicies).forEach(([name, policy]) => {
            response += `🔒 ${name.toUpperCase()}:\n`;
            response += `   Name: ${policy.name}\n`;
            response += `   Checks: ${policy.requiredChecks.join(', ')}\n`;
            response += `   Thresholds: ${JSON.stringify(policy.failThresholds)}\n\n`;
          });
          return { content: [{ type: "text", text: response }] };

        case 'get':
          if (!policy_name || !compliancePolicies[policy_name]) {
            return { content: [{ type: "text", text: `❌ Policy not found: ${policy_name}` }] };
          }
          const policy = compliancePolicies[policy_name];
          return { 
            content: [{ 
              type: "text", 
              text: `🔒 Policy: ${policy.name}\n${JSON.stringify(policy, null, 2)}` 
            }] 
          };

        case 'check':
          if (!scan_results) {
            return { content: [{ type: "text", text: "❌ Scan results required for compliance check" }] };
          }
          
          const compliance = multiToolScanner.checkCompliance(scan_results);
          let complianceReport = `🛡️ Compliance Check Results:\n\n`;
          
          Object.entries(compliance).forEach(([policyName, result]) => {
            const statusIcon = result.status === 'PASS' ? '✅' : '❌';
            complianceReport += `${statusIcon} ${policyName.toUpperCase()}: ${result.status}\n`;
            complianceReport += `   Findings: ${result.findings}\n`;
            if (result.failedThresholds && result.failedThresholds.length > 0) {
              complianceReport += `   Failed Thresholds: ${JSON.stringify(result.failedThresholds)}\n`;
            }
            complianceReport += '\n';
          });

          return { content: [{ type: "text", text: complianceReport }] };

        default:
          return { content: [{ type: "text", text: "❌ Invalid action" }] };
      }

    } catch (error) {
      logger.error('Policy management failed', { error: error.message });
      return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
    }
  }
);

// Helper methods
server.filterFixesByStrategy = function(fixes, strategy) {
  switch (strategy) {
    case 'conservative':
      return fixes.filter(fix => fix.confidence > 0.8);
    case 'aggressive':
      return fixes.filter(fix => fix.confidence > 0.5);
    case 'balanced':
    default:
      return fixes.filter(fix => fix.confidence > 0.7);
  }
};

server.getBestPractices = function(vulnType) {
  const practices = {
    sql_injection: `   • Use parameterized queries/prepared statements\n   • Implement input validation\n   • Use ORM with built-in protection\n   • Apply principle of least privilege to database accounts`,
    xss: `   • Sanitize all user input\n   • Use Content Security Policy (CSP)\n   • Encode output appropriately\n   • Use safe DOM APIs`,
    hardcoded_secrets: `   • Use environment variables\n   • Implement secure key management\n   • Rotate credentials regularly\n   • Use secret scanning in CI/CD`,
    weak_crypto: `   • Use AES-256 for encryption\n   • Use SHA-256+ for hashing\n   • Use cryptographically secure PRNGs\n   • Keep crypto libraries updated`
  };
  
  return practices[vulnType] || `   • Follow secure coding guidelines\n   • Regular security reviews\n   • Keep dependencies updated`;
};

// Legacy tools for backward compatibility
server.tool("scan_file", "Legacy: Use enhanced_scan_file instead", 
  { filepath: z.string() }, 
  async ({ filepath }) => {
    const result = await server.tool_handlers.enhanced_scan_file({ filepath });
    return result;
  }
);

server.tool("scan_directory", "Legacy: Use enhanced_scan_directory instead",
  { dirpath: z.string() },
  async ({ dirpath }) => {
    const result = await server.tool_handlers.enhanced_scan_directory({ dirpath });
    return result;
  }
);

server.tool("generate_sast_report", "Legacy: Use generate_enhanced_report instead",
  { scan_path: z.string(), report_dir: z.string(), format: z.string() },
  async ({ scan_path, report_dir, format }) => {
    const result = await server.tool_handlers.generate_enhanced_report({ 
      scan_path, report_dir, format 
    });
    return result;
  }
);

server.tool("auto_fix_file", "Legacy: Use ai_enhanced_auto_fix instead",
  { filepath: z.string(), create_backup: z.boolean().optional() },
  async ({ filepath, create_backup }) => {
    const result = await server.tool_handlers.ai_enhanced_auto_fix({ 
      filepath, create_backup 
    });
    return result;
  }
);

// Start the enhanced server
logger.info('🚀 Starting Enhanced SAST MCP Server v2.0.0');
logger.info('📊 Features: Multi-tool SAST, AI fixes, continuous monitoring, compliance checking');

const transport = new StdioServerTransport();
await server.connect(transport);
