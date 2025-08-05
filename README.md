# 🔍 Spotter-SAST: Advanced Security Analysis Tool

A comprehensive Model Context Protocol (MCP) server providing enterprise-grade Static Application Security Testing (SAST) with multi-tool integration, AI-powered analysis, continuous monitoring, and compliance checking.

## 🚀 Overview

Spotter-SAST is an advanced security analysis platform that combines multiple industry-standard SAST tools with intelligent automation, continuous monitoring, and comprehensive reporting. Built on the Model Context Protocol (MCP), it provides both real-time security analysis and long-term security posture management.

### 🎯 Key Features

- **🔧 Multi-Tool Integration**: Seamlessly integrates Semgrep, Bandit, ESLint, and njsscan
- **🤖 AI-Powered Fixes**: Intelligent vulnerability remediation with confidence scoring
- **👁️ Continuous Monitoring**: Real-time file system monitoring with automated alerts
- **📊 Advanced Reporting**: Multiple formats including HTML, JSON, Markdown, and SARIF
- **🛡️ Enterprise Security**: OAuth 2.0, RBAC, audit logging, and session management
- **📋 Compliance Checking**: OWASP Top 10, PCI DSS, and NIST framework mapping
- **📈 Security Dashboard**: Real-time metrics and trend analysis

## 🏗️ Architecture

### Core Components

1. **MultiToolScanner**: Orchestrates multiple SAST tools for comprehensive analysis
2. **SecurityManager**: Handles authentication, authorization, and audit logging
3. **ContinuousMonitor**: Provides real-time file monitoring and scheduled scans
4. **AdvancedReporting**: Generates comprehensive reports in multiple formats
5. **AIAutoFixer**: Intelligent vulnerability remediation with validation

### Supported Languages & Tools

| Language | Tools | Extensions |
|----------|-------|------------|
| **JavaScript/TypeScript** | Semgrep, ESLint, njsscan, Patterns | `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| **Python** | Semgrep, Bandit, Patterns | `.py`, `.pyw` |
| **Java/Kotlin** | Semgrep, Patterns | `.java`, `.kotlin` |
| **C#/.NET** | Semgrep, Patterns | `.cs`, `.vb` |
| **Go** | Semgrep, Patterns | `.go` |
| **PHP** | Semgrep, Patterns | `.php`, `.phtml` |
| **Ruby** | Semgrep, Patterns | `.rb`, `.erb` |
| **C/C++** | Semgrep, Patterns | `.c`, `.cpp`, `.h`, `.hpp` |
| **Rust** | Semgrep, Patterns | `.rs` |

## 🚀 Quick Start

### 1. Prerequisites

**Node.js Dependencies:**
```bash
npm install
```

**Python Security Tools:**
```bash
pip install -r requirements.txt
```

Required tools:
- [Semgrep](https://semgrep.dev/) - Multi-language static analysis
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [ESLint](https://eslint.org/) - JavaScript/TypeScript security rules

### 2. Configuration

Create environment configuration:
```bash
cp .env.example .env
```

Key environment variables:
```env
JWT_SECRET=your-secure-jwt-secret
ENABLE_RBAC=true
LOG_LEVEL=info
```

### 3. Launch Server

```bash
npm start
```

The server will start with:
- ✅ Multi-tool SAST capabilities
- ✅ Real-time file monitoring
- ✅ AI-powered auto-fixes
- ✅ Comprehensive reporting
- ✅ Security dashboard

## 🔧 Available Tools

### Core Scanning

#### `enhanced_scan_file`
Comprehensive multi-tool SAST scan for individual files
```json
{
  "filepath": "/path/to/file.js",
  "tools": ["semgrep", "eslint"],
  "policies": ["owasp", "pci"],
  "includeFixSuggestions": true,
  "user_token": "jwt-token"
}
```

#### `enhanced_scan_directory`
Directory-wide security analysis with monitoring
```json
{
  "dirpath": "/path/to/project",
  "enableMonitoring": true,
  "schedule": "0 */6 * * *",
  "policies": ["owasp", "enterprise_security"]
}
```

### AI-Powered Remediation

#### `ai_enhanced_auto_fix`
Intelligent vulnerability remediation with validation
```json
{
  "filepath": "/path/to/file.js",
  "strategy": "balanced",
  "validate_fixes": true,
  "create_backup": true
}
```

### Monitoring & Analytics

#### `start_continuous_monitoring`
Real-time security monitoring
```json
{
  "project_path": "/path/to/project",
  "schedule": "0 */6 * * *",
  "alert_thresholds": {
    "critical": 0,
    "high": 5
  }
}
```

#### `security_dashboard`
Real-time security metrics and alerts
```json
{
  "time_range": "24h",
  "include_trends": true,
  "include_alerts": true
}
```

### Reporting & Compliance

#### `generate_enhanced_report`
Comprehensive security reporting
```json
{
  "scan_path": "/path/to/project",
  "report_dir": "./reports",
  "format": "sarif",
  "include_executive_summary": true,
  "include_compliance_matrix": true
}
```

#### `manage_security_policies`
Policy and compliance management
```json
{
  "action": "check",
  "policy_name": "owasp",
  "scan_results": {...}
}
```

## 🛡️ Security & Compliance

### Vulnerability Detection

The system detects 9+ categories of security vulnerabilities:

| Category | OWASP Mapping | CWE | Severity |
|----------|---------------|-----|----------|
| **SQL Injection** | A03_Injection | CWE-89 | Critical |
| **Cross-Site Scripting** | A03_Injection | CWE-79 | High |
| **Hardcoded Secrets** | A02_Cryptographic_Failures | CWE-798 | Critical |
| **Command Injection** | A03_Injection | CWE-78 | Critical |
| **Weak Cryptography** | A02_Cryptographic_Failures | CWE-327 | Medium |
| **Path Traversal** | A01_Broken_Access_Control | CWE-22 | High |
| **Insecure Random** | A02_Cryptographic_Failures | CWE-338 | Medium |
| **Debug Code** | A09_Security_Logging_Monitoring_Failures | CWE-489 | Low |
| **Insecure Deserialization** | A08_Software_Data_Integrity_Failures | CWE-502 | High |

### Compliance Frameworks

- **OWASP Top 10 2021**: Automatic mapping and compliance checking
- **PCI DSS**: Payment card industry security standards
- **NIST**: Cybersecurity framework alignment
- **Custom Policies**: Organization-specific security rules

### Role-Based Access Control (RBAC)

| Role | Level | Key Permissions |
|------|-------|----------------|
| **Security Admin** | 4 | Full administrative access (`*`) |
| **Security Analyst** | 3 | Analysis, reporting, policy management |
| **Developer** | 2 | Scanning, fix suggestions, basic reporting |
| **Auditor** | 1 | Read-only access to scans and compliance |
| **Viewer** | 0 | Basic dashboard and report viewing |

## 📊 Reporting Formats

### Available Formats

- **HTML**: Interactive reports with charts and navigation
- **JSON**: Machine-readable structured data
- **Markdown**: Human-readable documentation format
- **SARIF**: Industry-standard Static Analysis Results Interchange Format
- **Dashboard**: Real-time web-based metrics and trends

### Report Contents

- 📈 **Executive Summary**: Risk scores, severity distribution, compliance status
- 🔍 **Detailed Findings**: Line-by-line vulnerability analysis with remediation
- 🏛️ **Compliance Matrix**: Framework-specific compliance checking
- 💡 **Recommendations**: Prioritized action items with impact assessment
- 📊 **Security Metrics**: Trends, tool effectiveness, and coverage analysis

## 🔄 Continuous Integration

### GitHub Actions Integration

```yaml
name: Spotter-SAST Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install Dependencies
        run: |
          npm install
          pip install -r requirements.txt
          
      - name: Run Security Scan
        run: |
          node server.js enhanced_scan_directory . --format=sarif
          
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/enhanced-sast-report.sarif
```

### Pre-commit Hooks

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: spotter-sast
        name: Spotter-SAST Security Scan
        entry: node server.js enhanced_scan_file
        language: system
        files: \.(js|ts|py|java|go|php|rb|rs)$
```

## 🚨 Monitoring & Alerting

### Real-time Monitoring

- **File System Watching**: Instant detection of code changes
- **Automated Scanning**: Triggered on file modifications
- **Smart Filtering**: Focuses on security-relevant file types
- **Performance Optimized**: Efficient resource usage with intelligent caching

### Alert Channels

- **Console Logging**: Immediate terminal notifications
- **File Logging**: Structured logging to `logs/` directory
- **Security Events**: Comprehensive audit trail
- **Webhook Support**: Integration with external systems (planned)

### Alert Types

- 🔴 **Critical Vulnerabilities**: Immediate attention required
- 🟠 **High Severity Issues**: Address within 7 days
- ⚖️ **Compliance Violations**: Policy threshold breaches
- 📊 **Performance Anomalies**: Scanning efficiency alerts
- 🔄 **Monitoring Failures**: System health notifications

## ⚙️ Configuration

### Environment Variables

```env
# Security Configuration
JWT_SECRET=your-256-bit-secret-key
ENABLE_RBAC=true
TOKEN_EXPIRY=24h

# Logging Configuration  
LOG_LEVEL=info
AUDIT_LOGGING=true

# Tool Configuration
SEMGREP_CONFIG=auto
BANDIT_CONFIG=bandit.yaml
ESLINT_CONFIG=.eslintrc.security.js

# Monitoring Configuration
DEFAULT_SCAN_SCHEDULE=0 */6 * * *
ALERT_THRESHOLD_CRITICAL=0
ALERT_THRESHOLD_HIGH=5
```

### Custom Security Policies

Edit `config/custom-policies.json`:
```json
{
  "organization_security": {
    "name": "Organization Security Policy",
    "requiredChecks": ["hardcoded_secrets", "weak_crypto"],
    "failThresholds": {
      "critical": 0,
      "high": 2,
      "medium": 10
    }
  }
}
```

### Role Customization

Modify `config/roles.json` to customize permissions for your organization's needs.

## 🛠️ Advanced Usage

### Custom Vulnerability Patterns

Add organization-specific patterns:
```javascript
// In server.js - vulnerabilityPatterns object
custom_api_leak: {
  patterns: [/your-org-api-key-pattern/gi],
  severity: "Critical",
  owaspCategory: "A02_Cryptographic_Failures",
  description: "Organization API key detected",
  remediation: "Move to secure environment variable"
}
```

### Integration Examples

#### CLI Usage
```bash
# Single file scan
node server.js enhanced_scan_file /path/to/file.js

# Directory scan with monitoring
node server.js enhanced_scan_directory /path/to/project --monitor

# Generate comprehensive report
node server.js generate_enhanced_report /path/to/project ./reports --format=html
```

#### Programmatic Usage
```javascript
import { McpClient } from "@modelcontextprotocol/sdk/client/mcp.js";

const client = new McpClient();
await client.connect();

const result = await client.callTool("enhanced_scan_file", {
  filepath: "/path/to/file.js",
  includeFixSuggestions: true
});
```

## 📈 Performance & Scalability

### Optimization Features

- **Parallel Tool Execution**: Multiple SAST tools run concurrently
- **Intelligent Caching**: Scan result caching for repeated analyses  
- **Incremental Scanning**: Only scan changed files in monitoring mode
- **Resource Management**: Memory and CPU optimization for large codebases
- **Batched Processing**: Efficient handling of large directory structures

### Performance Metrics

- **Scan Speed**: ~100-500 files/minute (depending on file size and complexity)
- **Memory Usage**: ~50-200MB base + ~1-5MB per concurrent file scan
- **Tool Detection**: Sub-second tool availability checking
- **Report Generation**: ~1-10 seconds for comprehensive reports

## 🔍 Troubleshooting

### Common Issues

1. **Tool Not Found**
   ```bash
   # Install missing tools
   pip install semgrep bandit
   npm install -g eslint
   ```

2. **Permission Denied**
   - Check RBAC configuration in `config/roles.json`
   - Verify JWT token validity
   - Ensure user has required permissions

3. **Memory Issues**
   ```bash
   # Increase Node.js heap size
   node --max-old-space-size=4096 server.js
   ```

4. **Authentication Failed**
   - Verify `JWT_SECRET` environment variable
   - Check token expiration settings
   - Review user role assignments

### Debug Mode

Enable detailed logging:
```bash
LOG_LEVEL=debug npm start
```

### Support

- 📖 **Documentation**: Comprehensive inline code documentation
- 🐛 **Issues**: GitHub Issues for bug reports and feature requests
- 💬 **Discussions**: GitHub Discussions for community support
- 📧 **Contact**: Maintainer contact via GitHub profile

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the Repository**
2. **Create Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Add Tests**: Ensure all new functionality is tested
4. **Follow Code Style**: Use existing patterns and conventions
5. **Update Documentation**: Include relevant documentation updates
6. **Submit Pull Request**: Clear description of changes and impact

### Development Setup

```bash
# Clone repository
git clone https://github.com/george-mellow/spotter-sast.git
cd spotter-sast

# Install dependencies
npm install
pip install -r requirements.txt

# Run in development mode
LOG_LEVEL=debug npm start
```

### Testing

```bash
# Run security scan on test files
npm test

# Run specific tool tests
node test/test-semgrep.js
node test/test-bandit.js
```

## 📋 Roadmap

### Upcoming Features

- [ ] **Web Dashboard**: Browser-based security dashboard
- [ ] **Slack/Teams Integration**: Real-time alert notifications
- [ ] **Docker Support**: Containerized deployment options
- [ ] **API Gateway**: RESTful API for external integrations
- [ ] **Machine Learning**: Enhanced vulnerability prediction
- [ ] **Plugin System**: Third-party tool integration framework

### Long-term Vision

- **🔮 Predictive Security**: ML-powered vulnerability prediction
- **🌐 Cloud Integration**: AWS/Azure/GCP native integrations
- **📱 Mobile Dashboard**: Mobile app for security monitoring
- **🤖 Advanced AI**: GPT-powered code analysis and fix generation

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 george-mellow

## 🚨 Security Notice

**Important**: This tool performs security analysis but does not guarantee complete security. Always complement automated scanning with:

- 👥 **Manual Security Reviews**: Expert human analysis
- 🎯 **Penetration Testing**: Real-world attack simulation  
- 🔄 **Dynamic Analysis (DAST)**: Runtime vulnerability testing
- 📦 **Dependency Scanning**: Third-party library security
- 🐳 **Container Security**: Docker/Kubernetes security scanning
- 🔐 **Infrastructure Security**: Cloud and network security assessment

## 📊 Project Stats

- **Languages**: JavaScript/Node.js, Python
- **Dependencies**: 10+ Node.js packages, 6+ Python packages
- **SAST Tools**: 4 integrated tools (Semgrep, Bandit, ESLint, njsscan)
- **Vulnerability Types**: 9+ categories with OWASP mapping
- **Report Formats**: 4 formats (HTML, JSON, Markdown, SARIF)
- **File Types**: 20+ supported file extensions
- **Compliance**: 3+ frameworks (OWASP, PCI DSS, NIST)

---

**🎯 Elevate your security posture with enterprise-grade SAST analysis powered by AI and industry-leading tools.**

*Built with ❤️ for secure software development*