// compliance-verification.js - Enhanced Compliance Verification Classes
// ====================================================================

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import winston from 'winston';

// Get the actual project directory (not the current working directory)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create logs directory with absolute path
const logDir = path.join(__dirname, 'logs');
try {
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
    }
} catch (error) {
    console.error('Could not create logs directory:', error.message);
    // Fall back to console logging only
}

// Winston configuration with absolute path
const logger = winston.createLogger({
    transports: [
        // Only add file transport if logs directory exists
        ...(fs.existsSync(logDir) ? [
            new winston.transports.File({
                filename: path.join(logDir, 'compliance.log')
            })
        ] : []),
        new winston.transports.Console()
    ]
});

// ===================================================================
// 1. COMPLIANCE DRIFT DETECTION SYSTEM
// ===================================================================

export class ComplianceDriftDetector {
  constructor() {
    this.baselineSnapshots = new Map();
    this.driftThresholds = {
      major: 0.15,    // 15% change triggers major alert
      minor: 0.05,    // 5% change triggers minor alert
      critical: 0.25  // 25% change triggers critical alert
    };
  }

  async createComplianceBaseline(projectPath, frameworks) {
    const timestamp = new Date().toISOString();
    
    // For demo purposes - in real implementation, this would scan the project
    const mockScanResult = {
      filepath: projectPath,
      aggregatedFindings: [
        {
          type: 'hardcoded_secrets',
          severity: 'Critical',
          file: 'config.js',
          line: 15,
          confidence: 'high'
        },
        {
          type: 'weak_crypto',
          severity: 'Medium', 
          file: 'utils.js',
          line: 42,
          confidence: 'medium'
        }
      ],
      complianceStatus: {
        hipaa: { status: 'FAIL', findings: 1 },
        gdpr: { status: 'PASS', findings: 0 },
        pci: { status: 'FAIL', findings: 1 }
      },
      riskScore: { score: 25, level: 'HIGH' }
    };
    
    const baseline = {
      timestamp,
      projectPath,
      frameworks,
      complianceScores: mockScanResult.complianceStatus,
      vulnerabilityCounts: this.countVulnerabilities(mockScanResult.aggregatedFindings),
      riskScore: mockScanResult.riskScore,
      totalFindings: mockScanResult.aggregatedFindings.length,
      fingerprint: this.generateComplianceFingerprint(mockScanResult)
    };

    this.baselineSnapshots.set(projectPath, baseline);
    
    // Save baseline to file for persistence
    const baselineDir = 'compliance-baselines';
    fs.mkdirSync(baselineDir, { recursive: true });
    const baselineFile = `${baselineDir}/${projectPath.replace(/[\/\\]/g, '_')}-baseline.json`;
    fs.writeFileSync(baselineFile, JSON.stringify(baseline, null, 2));
    
    complianceLogger.info('Compliance baseline created', { 
      projectPath, 
      frameworks, 
      totalFindings: baseline.totalFindings 
    });
    
    return baseline;
  }

  async detectComplianceDrift(projectPath, frameworks) {
    const baseline = this.baselineSnapshots.get(projectPath) || 
                    this.loadBaselineFromFile(projectPath);
    
    if (!baseline) {
      throw new Error('No baseline found. Create baseline first with createComplianceBaseline()');
    }

    // Mock current scan - in real implementation, this would perform actual scan
    const currentScanResult = {
      aggregatedFindings: [
        {
          type: 'hardcoded_secrets',
          severity: 'Critical',
          file: 'config.js',
          line: 15,
          confidence: 'high'
        },
        {
          type: 'weak_crypto',
          severity: 'Medium',
          file: 'utils.js', 
          line: 42,
          confidence: 'medium'
        },
        {
          type: 'sql_injection',
          severity: 'Critical',
          file: 'database.js',
          line: 28,
          confidence: 'high'
        }
      ],
      complianceStatus: {
        hipaa: { status: 'FAIL', findings: 2 },
        gdpr: { status: 'FAIL', findings: 1 },
        pci: { status: 'FAIL', findings: 2 }
      },
      riskScore: { score: 40, level: 'CRITICAL' }
    };

    const driftAnalysis = {
      timestamp: new Date().toISOString(),
      projectPath,
      baseline: baseline.timestamp,
      driftDetected: false,
      driftLevel: 'none',
      changes: [],
      recommendations: []
    };

    // Analyze compliance score drift
    Object.entries(currentScanResult.complianceStatus).forEach(([framework, status]) => {
      const baselineStatus = baseline.complianceScores[framework];
      if (baselineStatus) {
        const scoreChange = this.calculateScoreChange(baselineStatus, status);
        if (Math.abs(scoreChange) > this.driftThresholds.minor) {
          driftAnalysis.driftDetected = true;
          driftAnalysis.changes.push({
            type: 'compliance_score',
            framework,
            change: scoreChange,
            severity: this.getDriftSeverity(Math.abs(scoreChange)),
            oldStatus: baselineStatus.status,
            newStatus: status.status
          });
        }
      }
    });

    // Analyze vulnerability count drift
    const currentVulnCounts = this.countVulnerabilities(currentScanResult.aggregatedFindings);
    Object.entries(currentVulnCounts).forEach(([severity, count]) => {
      const baselineCount = baseline.vulnerabilityCounts[severity] || 0;
      const percentChange = baselineCount > 0 ? (count - baselineCount) / baselineCount : (count > 0 ? 1 : 0);
      
      if (Math.abs(percentChange) > this.driftThresholds.minor) {
        driftAnalysis.driftDetected = true;
        driftAnalysis.changes.push({
          type: 'vulnerability_count',
          severity,
          change: percentChange,
          oldCount: baselineCount,
          newCount: count,
          driftLevel: this.getDriftSeverity(Math.abs(percentChange))
        });
      }
    });

    // Set overall drift level
    if (driftAnalysis.changes.length > 0) {
      const maxDrift = Math.max(...driftAnalysis.changes.map(c => Math.abs(c.change || 0)));
      driftAnalysis.driftLevel = this.getDriftSeverity(maxDrift);
    }

    // Generate recommendations
    driftAnalysis.recommendations = this.generateDriftRecommendations(driftAnalysis.changes);

    complianceLogger.warn('Compliance drift detected', {
      projectPath,
      driftLevel: driftAnalysis.driftLevel,
      changes: driftAnalysis.changes.length
    });

    return driftAnalysis;
  }

  loadBaselineFromFile(projectPath) {
    try {
      const baselineFile = `compliance-baselines/${projectPath.replace(/[\/\\]/g, '_')}-baseline.json`;
      if (fs.existsSync(baselineFile)) {
        const baseline = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
        this.baselineSnapshots.set(projectPath, baseline);
        return baseline;
      }
    } catch (error) {
      complianceLogger.error('Failed to load baseline', { error: error.message });
    }
    return null;
  }

  getDriftSeverity(change) {
    if (change >= this.driftThresholds.critical) return 'critical';
    if (change >= this.driftThresholds.major) return 'major';
    if (change >= this.driftThresholds.minor) return 'minor';
    return 'none';
  }

  generateDriftRecommendations(changes) {
    const recommendations = [];
    
    changes.forEach(change => {
      switch (change.type) {
        case 'compliance_score':
          if (change.change < 0) {
            recommendations.push({
              priority: 'high',
              action: `Address compliance degradation in ${change.framework}`,
              description: `Compliance score dropped from ${change.oldStatus} to ${change.newStatus}`,
              timeframe: '7 days'
            });
          }
          break;
        case 'vulnerability_count':
          if (change.change > 0) {
            recommendations.push({
              priority: change.severity === 'critical' ? 'immediate' : 'high',
              action: `Investigate ${change.severity} vulnerability increase`,
              description: `${change.severity} vulnerabilities increased from ${change.oldCount} to ${change.newCount}`,
              timeframe: change.severity === 'critical' ? '24 hours' : '72 hours'
            });
          }
          break;
      }
    });

    return recommendations;
  }

  countVulnerabilities(findings) {
    return findings.reduce((counts, finding) => {
      const severity = finding.severity.toLowerCase();
      counts[severity] = (counts[severity] || 0) + 1;
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
  }

  generateComplianceFingerprint(scanResult) {
    const data = {
      vulnerabilities: scanResult.aggregatedFindings.length,
      compliance: Object.keys(scanResult.complianceStatus || {}),
      riskScore: scanResult.riskScore?.score || 0
    };
    return Buffer.from(JSON.stringify(data)).toString('base64');
  }

  calculateScoreChange(oldStatus, newStatus) {
    // Simple score calculation
    const oldScore = oldStatus.status === 'PASS' ? 1 : 0;
    const newScore = newStatus.status === 'PASS' ? 1 : 0;
    return newScore - oldScore;
  }
}

// ===================================================================
// 2. MULTI-TENANT COMPLIANCE MANAGEMENT
// ===================================================================

export class MultiTenantComplianceManager {
  constructor() {
    this.tenantConfigurations = new Map();
    this.complianceTemplates = this.loadComplianceTemplates();
  }

  loadComplianceTemplates() {
    return {
      healthcare_hipaa: {
        name: "Healthcare HIPAA Compliance",
        frameworks: ["hipaa", "nist"],
        riskTolerance: "zero",
        requiredControls: ["phi_protection", "encryption_at_rest", "access_controls"],
        alertThresholds: { critical: 0, high: 0, medium: 2 }
      },
      financial_pci: {
        name: "Financial PCI DSS Compliance", 
        frameworks: ["pci", "sox"],
        riskTolerance: "minimal",
        requiredControls: ["cardholder_data_protection", "secure_authentication"],
        alertThresholds: { critical: 0, high: 0, medium: 1 }
      },
      enterprise_standard: {
        name: "Enterprise Standard Compliance",
        frameworks: ["owasp", "nist"],
        riskTolerance: "low",
        requiredControls: ["access_controls", "encryption", "monitoring"],
        alertThresholds: { critical: 1, high: 5, medium: 15 }
      }
    };
  }

  async registerTenant(tenantId, configuration) {
    const tenantConfig = {
      id: tenantId,
      name: configuration.name,
      industry: configuration.industry,
      template: configuration.template,
      customFrameworks: configuration.customFrameworks || [],
      riskTolerance: configuration.riskTolerance || 'medium',
      contactEmail: configuration.contactEmail,
      complianceOfficer: configuration.complianceOfficer,
      registeredAt: new Date().toISOString(),
      lastAssessment: null,
      complianceStatus: 'pending'
    };

    // Apply template if specified
    if (configuration.template && this.complianceTemplates[configuration.template]) {
      const template = this.complianceTemplates[configuration.template];
      tenantConfig.frameworks = [...template.frameworks, ...tenantConfig.customFrameworks];
      tenantConfig.alertThresholds = template.alertThresholds;
      tenantConfig.requiredControls = template.requiredControls;
    }

    this.tenantConfigurations.set(tenantId, tenantConfig);
    
    // Save to persistent storage
    this.saveTenantConfiguration(tenantId, tenantConfig);
    
    complianceLogger.info('Tenant registered', { 
      tenantId, 
      name: tenantConfig.name,
      industry: tenantConfig.industry 
    });
    
    return tenantConfig;
  }

  async performTenantComplianceAssessment(tenantId, projectPath) {
    const tenantConfig = this.tenantConfigurations.get(tenantId) ||
                         this.loadTenantConfiguration(tenantId);
    
    if (!tenantConfig) {
      throw new Error(`Tenant ${tenantId} not found`);
    }

    const assessment = {
      tenantId,
      projectPath,
      timestamp: new Date().toISOString(),
      frameworks: tenantConfig.frameworks,
      riskTolerance: tenantConfig.riskTolerance,
      status: 'in_progress'
    };

    try {
      // Mock scan result - in real implementation, perform actual scan
      const mockScanResult = {
        aggregatedFindings: [
          {
            type: 'hardcoded_secrets',
            severity: 'Critical',
            file: 'config.js'
          }
        ],
        riskScore: { score: 30, level: 'HIGH' }
      };
      
      // Apply tenant-specific compliance analysis
      const tenantCompliance = await this.analyzeTenantCompliance(
        mockScanResult, 
        tenantConfig
      );

      assessment.status = 'completed';
      assessment.results = tenantCompliance;
      assessment.overallStatus = tenantCompliance.overallCompliance;
      assessment.actionItems = tenantCompliance.actionItems;

      // Update tenant's last assessment
      tenantConfig.lastAssessment = assessment.timestamp;
      tenantConfig.complianceStatus = assessment.overallStatus;

      // Generate tenant-specific notifications
      if (assessment.overallStatus === 'non_compliant') {
        await this.sendTenantNotification(tenantId, 'compliance_violation', assessment);
      }

      complianceLogger.info('Tenant assessment completed', {
        tenantId,
        overallStatus: assessment.overallStatus,
        actionItems: assessment.actionItems?.length || 0
      });

    } catch (error) {
      assessment.status = 'failed';
      assessment.error = error.message;
      complianceLogger.error('Tenant assessment failed', { tenantId, error: error.message });
    }

    return assessment;
  }

  async analyzeTenantCompliance(scanResult, tenantConfig) {
    const analysis = {
      timestamp: new Date().toISOString(),
      frameworks: {},
      overallCompliance: 'compliant',
      riskScore: scanResult.riskScore,
      actionItems: []
    };

    // Analyze each framework for the tenant
    for (const framework of tenantConfig.frameworks) {
      const frameworkAnalysis = {
        status: 'compliant',
        findings: 0,
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 }
      };

      // Apply tenant-specific risk tolerance
      const adjustedStatus = this.applyTenantRiskTolerance(
        frameworkAnalysis,
        tenantConfig.alertThresholds,
        tenantConfig.riskTolerance
      );

      analysis.frameworks[framework] = {
        status: adjustedStatus,
        findings: frameworkAnalysis.findings,
        severityCounts: frameworkAnalysis.severityCounts,
        tenantRiskTolerance: tenantConfig.riskTolerance
      };

      if (adjustedStatus === 'non_compliant') {
        analysis.overallCompliance = 'non_compliant';
      } else if (adjustedStatus === 'partial' && analysis.overallCompliance === 'compliant') {
        analysis.overallCompliance = 'partial';
      }
    }

    // Generate tenant-specific action items
    analysis.actionItems = this.generateTenantActionItems(
      scanResult.aggregatedFindings || [],
      tenantConfig,
      analysis.frameworks
    );

    return analysis;
  }

  applyTenantRiskTolerance(frameworkResult, tenantThresholds, riskTolerance) {
    // Mock logic for risk tolerance application
    switch (riskTolerance) {
      case 'zero':
        return 'non_compliant';
      case 'minimal':
        return 'partial';
      case 'low':
        return 'compliant';
      case 'medium':
        return 'compliant';
      default:
        return 'compliant';
    }
  }

  generateTenantActionItems(findings, tenantConfig, frameworkAnalysis) {
    const actionItems = [];
    
    // High-priority items based on tenant's risk tolerance
    if (tenantConfig.riskTolerance === 'zero') {
      findings.filter(f => f.severity === 'Critical' || f.severity === 'High').forEach(finding => {
        actionItems.push({
          priority: 'immediate',
          type: 'vulnerability',
          title: `Fix ${finding.severity} vulnerability: ${finding.type}`,
          description: finding.description || `${finding.severity} ${finding.type} vulnerability found`,
          file: finding.file,
          line: finding.line,
          dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
        });
      });
    }

    // Framework-specific action items
    Object.entries(frameworkAnalysis).forEach(([framework, analysis]) => {
      if (analysis.status === 'non_compliant') {
        actionItems.push({
          priority: 'high',
          type: 'compliance',
          title: `Address ${framework.toUpperCase()} compliance violations`,
          description: `Failed ${framework} compliance with ${analysis.findings} violations`,
          framework,
          dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
        });
      }
    });

    return actionItems.sort((a, b) => {
      const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
  }

  async sendTenantNotification(tenantId, type, data) {
    const tenantConfig = this.tenantConfigurations.get(tenantId);
    if (!tenantConfig) return;

    const notification = {
      tenantId,
      type,
      timestamp: new Date().toISOString(),
      recipient: tenantConfig.contactEmail,
      subject: this.getNotificationSubject(type, tenantConfig.name),
      data
    };

    // Log notification (in real implementation, this would send email/webhook)
    complianceLogger.warn('Tenant notification', notification);
    
    return notification;
  }

  getNotificationSubject(type, tenantName) {
    const subjects = {
      compliance_violation: `🚨 Compliance Violation Detected - ${tenantName}`,
      assessment_complete: `✅ Compliance Assessment Complete - ${tenantName}`,
      action_item_due: `⏰ Action Item Due Soon - ${tenantName}`
    };
    return subjects[type] || `Compliance Notification - ${tenantName}`;
  }

  saveTenantConfiguration(tenantId, config) {
    const configDir = 'config/tenants';
    fs.mkdirSync(configDir, { recursive: true });
    const configFile = `${configDir}/${tenantId}.json`;
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
  }

  loadTenantConfiguration(tenantId) {
    try {
      const configFile = `config/tenants/${tenantId}.json`;
      if (fs.existsSync(configFile)) {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        this.tenantConfigurations.set(tenantId, config);
        return config;
      }
    } catch (error) {
      complianceLogger.error('Failed to load tenant config', { tenantId, error: error.message });
    }
    return null;
  }
}

// ===================================================================
// 3. COMPLIANCE EVIDENCE COLLECTION & CHAIN OF CUSTODY
// ===================================================================

export class ComplianceEvidenceCollector {
  constructor() {
    this.evidenceChain = [];
    this.evidenceStore = new Map();
    this.cryptoSigning = true;
  }

  async collectComplianceEvidence(scanResult, frameworks, metadata = {}) {
    const evidenceId = this.generateEvidenceId();
    const timestamp = new Date().toISOString();
    
    const evidence = {
      id: evidenceId,
      timestamp,
      type: 'compliance_scan_evidence',
      collector: metadata.collector || 'system',
      frameworks,
      metadata: {
        ...metadata,
        scanTarget: scanResult.filepath || scanResult.dirpath || 'unknown',
        toolsUsed: Object.keys(scanResult.tools || {}),
        totalFindings: scanResult.aggregatedFindings?.length || 0
      },
      evidence: {
        scanResults: this.sanitizeEvidenceData(scanResult),
        complianceStatus: scanResult.complianceStatus,
        riskAssessment: scanResult.riskScore,
        vulnerabilityMapping: this.mapVulnerabilitiesToControls(
          scanResult.aggregatedFindings || [], 
          frameworks
        )
      },
      integrity: null,
      signature: null,
      chainOfCustody: [{
        action: 'collected',
        timestamp,
        actor: metadata.collector || 'system',
        notes: 'Evidence collected from automated compliance scan'
      }]
    };

    // Generate integrity hash
    evidence.integrity = this.generateEvidenceHash(evidence.evidence);
    
    // Sign evidence if enabled
    if (this.cryptoSigning) {
      evidence.signature = this.signEvidence(evidence);
    }

    // Store evidence
    this.evidenceStore.set(evidenceId, evidence);
    this.evidenceChain.push({
      id: evidenceId,
      timestamp,
      type: evidence.type,
      integrity: evidence.integrity
    });

    // Persist evidence to secure storage
    await this.persistEvidence(evidence);

    complianceLogger.info('Evidence collected', {
      evidenceId,
      frameworks,
      totalFindings: evidence.metadata.totalFindings
    });

    return {
      evidenceId,
      integrity: evidence.integrity,
      timestamp,
      summary: {
        frameworks: frameworks.length,
        findings: evidence.metadata.totalFindings,
        complianceStatus: this.summarizeComplianceStatus(scanResult.complianceStatus)
      }
    };
  }

  sanitizeEvidenceData(scanResult) {
    // Remove potentially sensitive data while preserving compliance-relevant information
    return {
      aggregatedFindings: scanResult.aggregatedFindings?.map(finding => ({
        id: finding.id || 'generated',
        type: finding.type,
        severity: finding.severity,
        file: path.basename(finding.file || 'unknown'), // Only basename for privacy
        line: finding.line,
        owaspCategory: finding.owaspCategory,
        cweId: finding.cweId,
        detectedBy: finding.detectedBy,
        confidence: finding.confidence
      })) || [],
      riskScore: scanResult.riskScore,
      timestamp: scanResult.timestamp || new Date().toISOString(),
      toolsUsed: Object.keys(scanResult.tools || {})
    };
  }

  mapVulnerabilitiesToControls(findings, frameworks) {
    const mapping = {};
    
    frameworks.forEach(framework => {
      mapping[framework] = {};
      findings.forEach(finding => {
        // Mock control mapping
        const controls = [`${framework.toUpperCase()}_${finding.type.toUpperCase()}_CONTROL`];
        controls.forEach(control => {
          if (!mapping[framework][control]) {
            mapping[framework][control] = [];
          }
          mapping[framework][control].push({
            type: finding.type,
            severity: finding.severity,
            file: path.basename(finding.file || 'unknown')
          });
        });
      });
    });

    return mapping;
  }

  generateEvidenceHash(evidence) {
    const evidenceString = JSON.stringify(evidence, Object.keys(evidence).sort());
    return crypto.createHash('sha256').update(evidenceString).digest('hex');
  }

  signEvidence(evidence) {
    // Simplified signing - in production use proper PKI
    const dataToSign = evidence.integrity + evidence.timestamp;
    return crypto.createHash('sha256').update(dataToSign + 'signing_key').digest('hex');
  }

  generateEvidenceId() {
    return 'EVD_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9).toUpperCase();
  }

  summarizeComplianceStatus(complianceStatus) {
    if (!complianceStatus) return 'unknown';
    
    const statuses = Object.values(complianceStatus).map(s => s.status);
    if (statuses.every(s => s === 'PASS')) return 'compliant';
    if (statuses.every(s => s === 'FAIL')) return 'non_compliant';
    return 'partial';
  }

  async persistEvidence(evidence) {
    const evidenceDir = 'compliance-evidence';
    fs.mkdirSync(evidenceDir, { recursive: true });
    
    const filename = `${evidenceDir}/${evidence.id}.json`;
    fs.writeFileSync(filename, JSON.stringify(evidence, null, 2));
    
    complianceLogger.info('Evidence persisted', { evidenceId: evidence.id, filename });
  }

  async generateComplianceAuditReport(frameworks, timeRange) {
    const startDate = new Date(timeRange.start);
    const endDate = new Date(timeRange.end);
    
    const relevantEvidence = Array.from(this.evidenceStore.values()).filter(evidence => {
      const evidenceDate = new Date(evidence.timestamp);
      return evidenceDate >= startDate && evidenceDate <= endDate &&
             evidence.frameworks.some(f => frameworks.includes(f));
    });

    const auditReport = {
      id: this.generateEvidenceId(),
      type: 'compliance_audit_report',
      timestamp: new Date().toISOString(),
      timeRange,
      frameworks,
      evidenceCount: relevantEvidence.length,
      summary: {
        totalScans: relevantEvidence.length,
        uniqueTargets: [...new Set(relevantEvidence.map(e => e.metadata.scanTarget))].length,
        complianceTrends: this.analyzeComplianceTrends(relevantEvidence),
        integrityVerification: this.verifyEvidenceIntegrity(relevantEvidence)
      },
      evidence: relevantEvidence.map(e => ({
        id: e.id,
        timestamp: e.timestamp,
        target: e.metadata.scanTarget,
        frameworks: e.frameworks,
        complianceStatus: this.summarizeComplianceStatus(e.evidence.complianceStatus),
        integrityValid: this.verifyEvidenceIntegrity([e]).allValid
      })),
      auditTrail: this.generateAuditTrail(relevantEvidence)
    };

    return auditReport;
  }

  analyzeComplianceTrends(evidence) {
    const trends = {};
    evidence.forEach(e => {
      const month = new Date(e.timestamp).toISOString().substr(0, 7);
      if (!trends[month]) trends[month] = { total: 0, compliant: 0 };
      trends[month].total++;
      if (this.summarizeComplianceStatus(e.evidence.complianceStatus) === 'compliant') {
        trends[month].compliant++;
      }
    });
    return trends;
  }

  verifyEvidenceIntegrity(evidence) {
    const results = evidence.map(e => ({
      id: e.id,
      valid: this.generateEvidenceHash(e.evidence) === e.integrity
    }));
    
    return {
      allValid: results.every(r => r.valid),
      totalChecked: results.length,
      validCount: results.filter(r => r.valid).length,
      invalidEvidence: results.filter(r => !r.valid).map(r => r.id)
    };
  }

  generateAuditTrail(evidence) {
    const trail = [];
    evidence.forEach(e => {
      e.chainOfCustody.forEach(custody => {
        trail.push({
          evidenceId: e.id,
          timestamp: custody.timestamp,
          action: custody.action,
          actor: custody.actor,
          notes: custody.notes
        });
      });
    });
    return trail.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }
}

// ===================================================================
// 4. AUTOMATED REMEDIATION WORKFLOWS
// ===================================================================

export class ComplianceRemediationEngine {
  constructor() {
    this.remediationWorkflows = this.initializeWorkflows();
    this.automationLevel = 'semi_automatic';
  }

  initializeWorkflows() {
    return {
      hipaa_phi_exposure: {
        name: "HIPAA PHI Exposure Remediation",
        triggers: ["hardcoded_secrets", "insufficient_encryption"],
        steps: [
          { action: "quarantine_affected_files", automated: true },
          { action: "notify_compliance_team", automated: true },
          { action: "generate_incident_report", automated: true },
          { action: "apply_security_patches", automated: false },
          { action: "verify_remediation", automated: false }
        ],
        sla: { hours: 4 },
        stakeholders: ["compliance_officer", "security_team", "development_team"]
      },
      
      pci_dss_cardholder_data: {
        name: "PCI DSS Cardholder Data Protection",
        triggers: ["cardholder_data_exposure", "weak_encryption"],
        steps: [
          { action: "isolate_affected_systems", automated: true },
          { action: "encrypt_cardholder_data", automated: false },
          { action: "update_access_controls", automated: false },
          { action: "compliance_validation", automated: false }
        ],
        sla: { hours: 2 },
        stakeholders: ["pci_compliance_officer", "security_team"]
      },

      gdpr_data_protection: {
        name: "GDPR Data Protection Remediation", 
        triggers: ["personal_data_exposure", "consent_violations"],
        steps: [
          { action: "assess_data_breach_scope", automated: false },
          { action: "notify_data_subjects", automated: false },
          { action: "report_to_supervisory_authority", automated: false },
          { action: "implement_protective_measures", automated: false }
        ],
        sla: { hours: 72 },
        stakeholders: ["dpo", "legal_team", "security_team"]
      }
    };
  }

  async triggerRemediationWorkflow(finding, framework, metadata = {}) {
    const workflowKey = `${framework}_${this.mapFindingToWorkflow(finding)}`;
    const workflow = this.remediationWorkflows[workflowKey];
    
    if (!workflow) {
      complianceLogger.warn('No remediation workflow found', { 
        finding: finding.type, 
        framework 
      });
      return null;
    }

    const workflowInstance = {
      id: this.generateWorkflowId(),
      workflowName: workflow.name,
      framework,
      finding,
      status: 'initiated',
      startTime: new Date().toISOString(),
      sla: new Date(Date.now() + workflow.sla.hours * 60 * 60 * 1000).toISOString(),
      steps: workflow.steps.map((step, index) => ({
        ...step,
        stepNumber: index + 1,
        status: 'pending',
        startTime: null,
        completionTime: null,
        notes: ''
      })),
      stakeholders: workflow.stakeholders,
      metadata,
      automationLevel: this.automationLevel
    };

    // Start workflow execution
    const result = await this.executeWorkflow(workflowInstance);
    
    complianceLogger.info('Remediation workflow initiated', {
      workflowId: workflowInstance.id,
      framework,
      finding: finding.type,
      sla: workflowInstance.sla
    });

    return result;
  }

  async executeWorkflow(workflowInstance) {
    complianceLogger.info('Executing remediation workflow', { 
      workflowId: workflowInstance.id, 
      name: workflowInstance.workflowName 
    });

    for (let i = 0; i < workflowInstance.steps.length; i++) {
      const step = workflowInstance.steps[i];
      step.startTime = new Date().toISOString();
      step.status = 'in_progress';

      try {
        if (step.automated && this.automationLevel !== 'manual') {
          await this.executeAutomatedStep(step, workflowInstance);
          step.status = 'completed';
          step.completionTime = new Date().toISOString();
        } else {
          // Manual step - create task and wait
          await this.createManualTask(step, workflowInstance);
          step.status = 'awaiting_manual_completion';
          
          // For demo purposes, we'll mark as pending
          if (this.automationLevel === 'automatic') {
            step.status = 'skipped';
            step.notes = 'Skipped in automatic mode';
          }
        }
      } catch (error) {
        step.status = 'failed';
        step.error = error.message;
        step.completionTime = new Date().toISOString();
        
        workflowInstance.status = 'failed';
        complianceLogger.error('Workflow step failed', { 
          workflowId: workflowInstance.id, 
          step: step.stepNumber, 
          error: error.message 
        });
        break;
      }
    }

    // Check if workflow is complete
    const completedSteps = workflowInstance.steps.filter(s => s.status === 'completed').length;
    const totalSteps = workflowInstance.steps.length;
    
    if (completedSteps === totalSteps) {
      workflowInstance.status = 'completed';
      workflowInstance.completionTime = new Date().toISOString();
    } else if (workflowInstance.status !== 'failed') {
      workflowInstance.status = 'in_progress';
    }

    return workflowInstance;
  }

  async executeAutomatedStep(step, workflowInstance) {
    switch (step.action) {
      case 'quarantine_affected_files':
        await this.quarantineFiles(workflowInstance.finding);
        step.notes = 'Files quarantined successfully';
        break;
        
      case 'notify_compliance_team':
        await this.sendNotification(
          workflowInstance.stakeholders,
          'compliance_violation',
          workflowInstance
        );
        step.notes = 'Stakeholders notified';
        break;
        
      case 'generate_incident_report':
        const report = await this.generateIncidentReport(workflowInstance);
        step.notes = `Incident report generated: ${report.id}`;
        break;
        
      case 'isolate_affected_systems':
        await this.isolateAffectedSystems(workflowInstance.finding);
        step.notes = 'Systems isolated successfully';
        break;
        
      default:
        throw new Error(`Unknown automated action: ${step.action}`);
    }
  }

  async createManualTask(step, workflowInstance) {
    const task = {
      id: this.generateTaskId(),
      workflowId: workflowInstance.id,
      stepNumber: step.stepNumber,
      action: step.action,
      title: this.getStepTitle(step.action),
      description: this.getStepDescription(step.action, workflowInstance),
      assignees: workflowInstance.stakeholders,
      dueDate: workflowInstance.sla,
      status: 'open',
      createdAt: new Date().toISOString()
    };

    complianceLogger.info('Manual task created', task);
    return task;
  }

  async quarantineFiles(finding) {
    const quarantineDir = 'quarantine';
    fs.mkdirSync(quarantineDir, { recursive: true });
    
    const originalFile = finding.file;
    if (originalFile) {
      const quarantineFile = path.join(quarantineDir, path.basename(originalFile) + '.quarantined');
      
      // In real implementation, copy file to quarantine
      complianceLogger.warn('File quarantined', { original: originalFile, quarantine: quarantineFile });
    }
  }

  async isolateAffectedSystems(finding) {
    complianceLogger.warn('System isolation triggered', { 
      file: finding.file, 
      vulnerability: finding.type 
    });
  }

  async sendNotification(stakeholders, type, workflowInstance) {
    const notifications = stakeholders.map(stakeholder => ({
      recipient: stakeholder,
      type,
      subject: `Compliance Remediation Required: ${workflowInstance.workflowName}`,
      body: `Workflow ${workflowInstance.id} has been initiated for ${workflowInstance.framework} compliance violation.`,
      timestamp: new Date().toISOString()
    }));

    notifications.forEach(notification => {
      complianceLogger.info('Compliance notification sent', notification);
    });

    return notifications;
  }

  async generateIncidentReport(workflowInstance) {
    const report = {
      id: this.generateReportId(),
      type: 'compliance_incident',
      workflowId: workflowInstance.id,
      framework: workflowInstance.framework,
      timestamp: new Date().toISOString(),
      finding: workflowInstance.finding,
      severity: workflowInstance.finding.severity,
      affectedSystems: [workflowInstance.finding.file],
      stakeholders: workflowInstance.stakeholders,
      sla: workflowInstance.sla,
      status: 'open'
    };

    // Save incident report
    const reportsDir = 'incident-reports';
    fs.mkdirSync(reportsDir, { recursive: true });
    fs.writeFileSync(
      `${reportsDir}/${report.id}.json`,
      JSON.stringify(report, null, 2)
    );

    return report;
  }

  mapFindingToWorkflow(finding) {
    const mapping = {
      'hardcoded_secrets': 'phi_exposure',
      'weak_crypto': 'cardholder_data',
      'insufficient_encryption': 'data_protection'
    };
    return mapping[finding.type] || 'general';
  }

  getStepTitle(action) {
    const titles = {
      'apply_security_patches': 'Apply Security Patches',
      'verify_remediation': 'Verify Remediation Effectiveness',
      'encrypt_cardholder_data': 'Encrypt Cardholder Data',
      'update_access_controls': 'Update Access Controls',
      'compliance_validation': 'Validate Compliance Requirements'
    };
    return titles[action] || action.replace(/_/g, ' ').toUpperCase();
  }

  getStepDescription(action, workflowInstance) {
    return `Complete ${this.getStepTitle(action)} for workflow ${workflowInstance.id} - ${workflowInstance.workflowName}`;
  }

  generateWorkflowId() {
    return 'WF_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 6).toUpperCase();
  }

  generateTaskId() {
    return 'TASK_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 6).toUpperCase();
  }

  generateReportId() {
    return 'RPT_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 6).toUpperCase();
  }
}

// ===================================================================
// EXPORT ALL CLASSES
// ===================================================================

export default {
  ComplianceDriftDetector,
  MultiTenantComplianceManager,
  ComplianceEvidenceCollector,
  ComplianceRemediationEngine
};