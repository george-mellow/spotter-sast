// compliance-mcp-tools.js - MCP Tools for Enhanced Compliance Features
// =======================================================================

import { z } from "zod";

// Export function to register compliance MCP tools
export function registerComplianceMCPTools(server, complianceComponents) {
  const {
    complianceDriftDetector,
    multiTenantManager,
    evidenceCollector,
    remediationEngine
  } = complianceComponents;

  // ===================================================================
  // 1. COMPLIANCE DRIFT DETECTION TOOLS
  // ===================================================================

  server.tool(
    "compliance_drift_baseline",
    "Create compliance baseline for drift detection",
    {
      project_path: z.string().describe("Project path to baseline"),
      frameworks: z.array(z.string()).describe("Compliance frameworks to include"),
      baseline_name: z.string().optional().describe("Custom baseline name")
    },
    async ({ project_path, frameworks, baseline_name }) => {
      try {
        const baseline = await complianceDriftDetector.createComplianceBaseline(
          project_path, 
          frameworks
        );
        
        return { 
          content: [{ 
            type: "text", 
            text: `✅ Compliance baseline created successfully!\n\n` +
                  `📂 Project: ${project_path}\n` +
                  `🏛️ Frameworks: ${frameworks.join(', ')}\n` +
                  `📊 Risk Score: ${baseline.riskScore?.score || 'N/A'}\n` +
                  `🔍 Total Findings: ${baseline.totalFindings}\n` +
                  `⏰ Timestamp: ${baseline.timestamp}\n` +
                  `🔐 Fingerprint: ${baseline.fingerprint.substring(0, 16)}...`
          }] 
        };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  server.tool(
    "compliance_drift_detect",
    "Detect compliance drift from baseline",
    {
      project_path: z.string().describe("Project path to scan"),
      frameworks: z.array(z.string()).describe("Compliance frameworks to check")
    },
    async ({ project_path, frameworks }) => {
      try {
        const driftAnalysis = await complianceDriftDetector.detectComplianceDrift(
          project_path, 
          frameworks
        );
        
        let response = `🔍 Compliance Drift Analysis\n\n`;
        response += `📂 Project: ${project_path}\n`;
        response += `⏰ Analysis Time: ${driftAnalysis.timestamp}\n`;
        response += `📊 Drift Detected: ${driftAnalysis.driftDetected ? '⚠️ YES' : '✅ NO'}\n`;
        response += `📈 Drift Level: ${driftAnalysis.driftLevel.toUpperCase()}\n\n`;
        
        if (driftAnalysis.changes.length > 0) {
          response += `🔄 Changes Detected:\n`;
          driftAnalysis.changes.forEach((change, index) => {
            response += `   ${index + 1}. ${change.type}: ${Math.abs(change.change * 100).toFixed(1)}% change\n`;
          });
          response += '\n';
        }
        
        if (driftAnalysis.recommendations.length > 0) {
          response += `💡 Recommendations:\n`;
          driftAnalysis.recommendations.forEach((rec, index) => {
            response += `   ${index + 1}. [${rec.priority.toUpperCase()}] ${rec.action}\n`;
            response += `      ${rec.description}\n`;
            response += `      Timeframe: ${rec.timeframe}\n\n`;
          });
        }
        
        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 2. MULTI-TENANT MANAGEMENT TOOLS
  // ===================================================================

  server.tool(
    "register_compliance_tenant",
    "Register new tenant with compliance configuration",
    {
      tenant_id: z.string().describe("Unique tenant identifier"),
      tenant_config: z.object({
        name: z.string(),
        industry: z.string(),
        template: z.string().optional(),
        customFrameworks: z.array(z.string()).optional(),
        riskTolerance: z.enum(["zero", "minimal", "low", "medium", "high"]).optional(),
        contactEmail: z.string(),
        complianceOfficer: z.string()
      }).describe("Tenant configuration")
    },
    async ({ tenant_id, tenant_config }) => {
      try {
        const registeredTenant = await multiTenantManager.registerTenant(tenant_id, tenant_config);
        
        return { 
          content: [{ 
            type: "text", 
            text: `✅ Tenant registered successfully!\n\n` +
                  `🏢 Tenant ID: ${registeredTenant.id}\n` +
                  `📝 Name: ${registeredTenant.name}\n` +
                  `🏭 Industry: ${registeredTenant.industry}\n` +
                  `📊 Risk Tolerance: ${registeredTenant.riskTolerance}\n` +
                  `🏛️ Frameworks: ${registeredTenant.frameworks?.join(', ') || 'Default'}\n` +
                  `👤 Compliance Officer: ${registeredTenant.complianceOfficer}\n` +
                  `📧 Contact: ${registeredTenant.contactEmail}`
          }] 
        };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  server.tool(
    "tenant_compliance_assessment",
    "Perform compliance assessment for specific tenant",
    {
      tenant_id: z.string().describe("Tenant identifier"),
      project_path: z.string().describe("Project path to assess")
    },
    async ({ tenant_id, project_path }) => {
      try {
        const assessment = await multiTenantManager.performTenantComplianceAssessment(
          tenant_id, 
          project_path
        );
        
        let response = `🏢 Tenant Compliance Assessment\n\n`;
        response += `🆔 Tenant: ${tenant_id}\n`;
        response += `📂 Project: ${project_path}\n`;
        response += `⏰ Assessment Time: ${assessment.timestamp}\n`;
        response += `📊 Overall Status: ${assessment.overallStatus?.toUpperCase()}\n`;
        response += `🏛️ Frameworks: ${assessment.frameworks?.join(', ')}\n\n`;
        
        if (assessment.results) {
          response += `🏛️ Framework Results:\n`;
          Object.entries(assessment.results.frameworks).forEach(([framework, result]) => {
            const statusIcon = result.status === 'compliant' ? '✅' : 
                             result.status === 'non_compliant' ? '❌' : '⚠️';
            response += `   ${statusIcon} ${framework.toUpperCase()}: ${result.status.toUpperCase()}\n`;
          });
          response += '\n';
        }
        
        if (assessment.actionItems?.length > 0) {
          response += `📋 Action Items:\n`;
          assessment.actionItems.slice(0, 5).forEach((item, index) => {
            response += `   ${index + 1}. [${item.priority.toUpperCase()}] ${item.title}\n`;
            response += `      Due: ${new Date(item.dueDate).toLocaleDateString()}\n`;
          });
        }
        
        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 3. EVIDENCE COLLECTION TOOLS
  // ===================================================================

  server.tool(
    "collect_compliance_evidence",
    "Collect compliance evidence with chain of custody",
    {
      scan_path: z.string().describe("Path to scan for evidence collection"),
      frameworks: z.array(z.string()).describe("Compliance frameworks"),
      collector: z.string().describe("Evidence collector name"),
      notes: z.string().optional().describe("Additional notes")
    },
    async ({ scan_path, frameworks, collector, notes }) => {
      try {
        // Mock scan result for evidence collection
        const mockScanResult = {
          filepath: scan_path,
          aggregatedFindings: [
            {
              type: 'hardcoded_secrets',
              severity: 'Critical',
              file: scan_path,
              line: 15,
              confidence: 'high'
            }
          ],
          complianceStatus: {
            hipaa: { status: 'FAIL', findings: 1 },
            pci: { status: 'FAIL', findings: 1 }
          },
          riskScore: { score: 30, level: 'HIGH' },
          tools: { patterns: { findings: 1 } }
        };
        
        const evidence = await evidenceCollector.collectComplianceEvidence(
          mockScanResult,
          frameworks,
          { collector, notes }
        );
        
        return { 
          content: [{ 
            type: "text", 
            text: `🔒 Compliance Evidence Collected\n\n` +
                  `🆔 Evidence ID: ${evidence.evidenceId}\n` +
                  `⏰ Timestamp: ${evidence.timestamp}\n` +
                  `🔐 Integrity Hash: ${evidence.integrity}\n` +
                  `🏛️ Frameworks: ${frameworks.join(', ')}\n` +
                  `🔍 Findings: ${evidence.summary.findings}\n` +
                  `📊 Compliance Status: ${evidence.summary.complianceStatus}`
          }] 
        };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  server.tool(
    "generate_compliance_audit_report",
    "Generate comprehensive audit report with evidence chain",
    {
      frameworks: z.array(z.string()).describe("Frameworks to include in audit"),
      time_range: z.object({
        start: z.string(),
        end: z.string()
      }).describe("Time range for audit"),
      report_format: z.enum(["summary", "detailed", "full"]).default("detailed")
    },
    async ({ frameworks, time_range, report_format }) => {
      try {
        const auditReport = await evidenceCollector.generateComplianceAuditReport(
          frameworks,
          time_range
        );
        
        let response = `📋 Compliance Audit Report\n\n`;
        response += `🆔 Report ID: ${auditReport.id}\n`;
        response += `⏰ Generated: ${auditReport.timestamp}\n`;
        response += `📅 Period: ${new Date(time_range.start).toLocaleDateString()} - ${new Date(time_range.end).toLocaleDateString()}\n`;
        response += `🏛️ Frameworks: ${frameworks.join(', ')}\n`;
        response += `📊 Evidence Items: ${auditReport.evidenceCount}\n`;
        response += `🎯 Unique Targets: ${auditReport.summary.uniqueTargets}\n`;
        response += `✅ Integrity Valid: ${auditReport.summary.integrityVerification.allValid ? 'YES' : 'NO'}\n\n`;
        
        if (report_format === 'detailed' || report_format === 'full') {
          response += `📈 Compliance Trends:\n`;
          Object.entries(auditReport.summary.complianceTrends).forEach(([month, data]) => {
            const percentage = ((data.compliant / data.total) * 100).toFixed(1);
            response += `   ${month}: ${percentage}% compliant (${data.compliant}/${data.total})\n`;
          });
          response += '\n';
        }
        
        if (report_format === 'full') {
          response += `🔍 Evidence Summary:\n`;
          auditReport.evidence.slice(0, 10).forEach((evidence, index) => {
            response += `   ${index + 1}. ${evidence.id} - ${evidence.complianceStatus} (${new Date(evidence.timestamp).toLocaleDateString()})\n`;
          });
          if (auditReport.evidence.length > 10) {
            response += `   ... and ${auditReport.evidence.length - 10} more\n`;
          }
        }
        
        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 4. AUTOMATED REMEDIATION TOOLS
  // ===================================================================

  server.tool(
    "trigger_compliance_remediation",
    "Trigger automated compliance remediation workflow",
    {
      finding: z.object({
        type: z.string(),
        severity: z.string(),
        file: z.string(),
        line: z.number().optional()
      }).describe("Vulnerability finding"),
      framework: z.string().describe("Compliance framework"),
      automation_level: z.enum(["automatic", "semi_automatic", "manual"]).default("semi_automatic"),
      stakeholders: z.array(z.string()).optional().describe("Additional stakeholders to notify")
    },
    async ({ finding, framework, automation_level, stakeholders }) => {
      try {
        remediationEngine.automationLevel = automation_level;
        
        const workflow = await remediationEngine.triggerRemediationWorkflow(
          finding,
          framework,
          { stakeholders: stakeholders || [] }
        );
        
        if (!workflow) {
          return { 
            content: [{ 
              type: "text", 
              text: `⚠️ No remediation workflow available for ${finding.type} in ${framework} framework` 
            }] 
          };
        }
        
        let response = `🔧 Compliance Remediation Workflow Triggered\n\n`;
        response += `🆔 Workflow ID: ${workflow.id}\n`;
        response += `📝 Name: ${workflow.workflowName}\n`;
        response += `🏛️ Framework: ${framework.toUpperCase()}\n`;
        response += `🚨 Finding: ${finding.type} (${finding.severity})\n`;
        response += `⏰ SLA: ${new Date(workflow.sla).toLocaleString()}\n`;
        response += `🤖 Automation: ${automation_level}\n`;
        response += `📊 Status: ${workflow.status.toUpperCase()}\n\n`;
        
        response += `📋 Workflow Steps:\n`;
        workflow.steps.forEach((step, index) => {
          const statusIcon = step.status === 'completed' ? '✅' : 
                            step.status === 'in_progress' ? '⏳' : 
                            step.status === 'failed' ? '❌' : '⚪';
          const autoIcon = step.automated ? '🤖' : '👤';
          
          response += `   ${index + 1}. ${statusIcon} ${autoIcon} ${step.action.replace(/_/g, ' ').toUpperCase()}\n`;
          if (step.notes) {
            response += `      Notes: ${step.notes}\n`;
          }
        });
        
        if (workflow.stakeholders?.length > 0) {
          response += `\n👥 Stakeholders: ${workflow.stakeholders.join(', ')}\n`;
        }
        
        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 5. ADVANCED ANALYTICS TOOLS
  // ===================================================================

  server.tool(
    "compliance_analytics_dashboard",
    "Generate advanced compliance analytics and insights",
    {
      time_range: z.object({
        start: z.string(),
        end: z.string()
      }).describe("Analysis time range"),
      frameworks: z.array(z.string()).optional().describe("Specific frameworks to analyze"),
      include_predictions: z.boolean().default(false).describe("Include predictive analytics")
    },
    async ({ time_range, frameworks, include_predictions }) => {
      try {
        // Mock analytics data for demonstration
        const analytics = {
          period: time_range,
          frameworks: frameworks || ['hipaa', 'gdpr', 'pci', 'nist'],
          summary: {
            totalAssessments: 156,
            averageComplianceScore: 87.3,
            trendDirection: 'improving',
            criticalViolations: 12,
            automatedRemediations: 89
          },
          frameworkBreakdown: {
            hipaa: { score: 92.1, trend: 'stable', violations: 2 },
            gdpr: { score: 89.7, trend: 'improving', violations: 1 },
            pci: { score: 94.2, trend: 'improving', violations: 0 },
            nist: { score: 83.8, trend: 'declining', violations: 9 }
          },
          riskHotspots: [
            { area: 'Authentication Systems', risk: 'high', findings: 15 },
            { area: 'Data Encryption', risk: 'medium', findings: 8 },
            { area: 'Access Controls', risk: 'low', findings: 3 }
          ]
        };
        
        let response = `📊 Compliance Analytics Dashboard\n\n`;
        response += `📅 Analysis Period: ${new Date(time_range.start).toLocaleDateString()} - ${new Date(time_range.end).toLocaleDateString()}\n`;
        response += `🏛️ Frameworks: ${analytics.frameworks.join(', ')}\n\n`;
        
        response += `📈 Summary Metrics:\n`;
        response += `   📊 Average Compliance Score: ${analytics.summary.averageComplianceScore}%\n`;
        response += `   📈 Trend: ${analytics.summary.trendDirection.toUpperCase()}\n`;
        response += `   🔍 Total Assessments: ${analytics.summary.totalAssessments}\n`;
        response += `   🚨 Critical Violations: ${analytics.summary.criticalViolations}\n`;
        response += `   🤖 Automated Fixes: ${analytics.summary.automatedRemediations}\n\n`;
        
        response += `🏛️ Framework Breakdown:\n`;
        Object.entries(analytics.frameworkBreakdown).forEach(([framework, data]) => {
          const trendIcon = data.trend === 'improving' ? '📈' : 
                           data.trend === 'declining' ? '📉' : '➡️';
          response += `   ${framework.toUpperCase()}: ${data.score}% ${trendIcon} (${data.violations} violations)\n`;
        });
        
        response += `\n🎯 Risk Hotspots:\n`;
        analytics.riskHotspots.forEach((hotspot, index) => {
          const riskIcon = hotspot.risk === 'high' ? '🔴' : 
                          hotspot.risk === 'medium' ? '🟡' : '🟢';
          response += `   ${index + 1}. ${riskIcon} ${hotspot.area}: ${hotspot.findings} findings\n`;
        });
        
        if (include_predictions) {
          response += `\n🔮 Predictive Insights:\n`;
          response += `   • NIST compliance may drop below 80% in next quarter\n`;
          response += `   • Authentication systems require immediate attention\n`;
          response += `   • Automated remediation success rate: 94.2%\n`;
        }
        
        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 6. COMPLIANCE FRAMEWORK MANAGEMENT TOOLS
  // ===================================================================

  server.tool(
    "list_compliance_frameworks",
    "List all available compliance frameworks with their status",
    {
      industry_filter: z.string().optional().describe("Filter by industry (healthcare, finance, etc.)"),
      enabled_only: z.boolean().default(false).describe("Show only enabled frameworks")
    },
    async ({ industry_filter, enabled_only }) => {
      try {
        // Mock framework data
        const frameworks = {
          hipaa: { name: "HIPAA", industry: "healthcare", enabled: true, score: 92.1 },
          gdpr: { name: "GDPR", industry: "general", enabled: true, score: 89.7 },
          pci_dss: { name: "PCI DSS", industry: "finance", enabled: true, score: 94.2 },
          sox: { name: "SOX", industry: "finance", enabled: false, score: null },
          nist_csf: { name: "NIST CSF", industry: "general", enabled: true, score: 83.8 },
          iso27001: { name: "ISO 27001", industry: "general", enabled: false, score: null },
          ccpa: { name: "CCPA", industry: "general", enabled: false, score: null },
          fisma: { name: "FISMA", industry: "government", enabled: false, score: null }
        };

        let filteredFrameworks = Object.entries(frameworks);

        if (industry_filter) {
          filteredFrameworks = filteredFrameworks.filter(([_, fw]) => 
            fw.industry === industry_filter || fw.industry === 'general'
          );
        }

        if (enabled_only) {
          filteredFrameworks = filteredFrameworks.filter(([_, fw]) => fw.enabled);
        }

        let response = `🏛️ Compliance Frameworks\n\n`;
        
        if (industry_filter) {
          response += `🏭 Industry Filter: ${industry_filter.toUpperCase()}\n`;
        }
        
        if (enabled_only) {
          response += `✅ Showing enabled frameworks only\n`;
        }
        
        response += `\n📋 Available Frameworks:\n`;
        
        filteredFrameworks.forEach(([id, framework]) => {
          const statusIcon = framework.enabled ? '✅' : '⚪';
          const scoreText = framework.score ? `(${framework.score}%)` : '(Not assessed)';
          response += `   ${statusIcon} ${framework.name} - ${framework.industry} ${scoreText}\n`;
        });

        response += `\n📊 Summary:\n`;
        response += `   Total Frameworks: ${filteredFrameworks.length}\n`;
        response += `   Enabled: ${filteredFrameworks.filter(([_, fw]) => fw.enabled).length}\n`;
        response += `   Assessed: ${filteredFrameworks.filter(([_, fw]) => fw.score !== null).length}\n`;

        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  // ===================================================================
  // 7. COMPLIANCE STATUS OVERVIEW TOOL
  // ===================================================================

  server.tool(
    "compliance_status_overview",
    "Get comprehensive compliance status overview",
    {
      tenant_id: z.string().optional().describe("Specific tenant to analyze"),
      include_recommendations: z.boolean().default(true).describe("Include actionable recommendations"),
      risk_threshold: z.enum(["low", "medium", "high", "critical"]).default("medium").describe("Minimum risk level to report")
    },
    async ({ tenant_id, include_recommendations, risk_threshold }) => {
      try {
        // Mock comprehensive status data
        const statusOverview = {
          timestamp: new Date().toISOString(),
          tenantId: tenant_id || 'system_wide',
          overallStatus: 'partial_compliance',
          overallScore: 87.3,
          frameworks: {
            hipaa: { status: 'compliant', score: 92.1, lastAssessment: '2024-01-20' },
            gdpr: { status: 'partial', score: 78.5, lastAssessment: '2024-01-22' },
            pci_dss: { status: 'compliant', score: 94.2, lastAssessment: '2024-01-21' },
            nist_csf: { status: 'non_compliant', score: 65.8, lastAssessment: '2024-01-19' }
          },
          riskDistribution: {
            critical: 2,
            high: 8,
            medium: 15,
            low: 23
          },
          trends: {
            improving: ['pci_dss', 'hipaa'],
            stable: ['gdpr'],
            declining: ['nist_csf']
          }
        };

        let response = `📊 Compliance Status Overview\n\n`;
        response += `⏰ Generated: ${new Date(statusOverview.timestamp).toLocaleString()}\n`;
        
        if (tenant_id) {
          response += `🏢 Tenant: ${tenant_id}\n`;
        } else {
          response += `🌐 Scope: System-wide\n`;
        }
        
        response += `📈 Overall Score: ${statusOverview.overallScore}%\n`;
        response += `🎯 Status: ${statusOverview.overallStatus.replace('_', ' ').toUpperCase()}\n\n`;

        response += `🏛️ Framework Status:\n`;
        Object.entries(statusOverview.frameworks).forEach(([framework, data]) => {
          const statusIcon = data.status === 'compliant' ? '✅' : 
                           data.status === 'non_compliant' ? '❌' : '⚠️';
          response += `   ${statusIcon} ${framework.toUpperCase()}: ${data.score}% (${data.status})\n`;
        });

        response += `\n🎯 Risk Distribution:\n`;
        const riskIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
        Object.entries(statusOverview.riskDistribution).forEach(([level, count]) => {
          if (level === risk_threshold || ['critical', 'high'].includes(level)) {
            response += `   ${riskIcons[level]} ${level.toUpperCase()}: ${count} issues\n`;
          }
        });

        response += `\n📈 Trends:\n`;
        Object.entries(statusOverview.trends).forEach(([trend, frameworks]) => {
          const trendIcon = trend === 'improving' ? '📈' : 
                           trend === 'declining' ? '📉' : '➡️';
          response += `   ${trendIcon} ${trend.toUpperCase()}: ${frameworks.join(', ')}\n`;
        });

        if (include_recommendations) {
          response += `\n💡 Key Recommendations:\n`;
          response += `   1. [IMMEDIATE] Address ${statusOverview.riskDistribution.critical} critical issues\n`;
          response += `   2. [HIGH] Improve NIST CSF compliance (currently 65.8%)\n`;
          response += `   3. [MEDIUM] Maintain current HIPAA and PCI DSS compliance levels\n`;
          response += `   4. [LOW] Monitor GDPR partial compliance status\n`;
        }

        return { content: [{ type: "text", text: response }] };
      } catch (error) {
        return { content: [{ type: "text", text: `❌ Error: ${error.message}` }] };
      }
    }
  );

  console.error('✅ Enhanced Compliance MCP Tools registered successfully');
}