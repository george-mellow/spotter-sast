#!/bin/bash
# Spotter-SAST Compliance Management Script
# =========================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
CONFIG_DIR="$PROJECT_DIR/config"
REPORTS_DIR="$PROJECT_DIR/compliance-reports"
EVIDENCE_DIR="$PROJECT_DIR/compliance-evidence"

# Ensure directories exist
mkdir -p "$REPORTS_DIR" "$EVIDENCE_DIR"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ===========================================
# Framework Management Functions
# ===========================================

list_frameworks() {
    log_info "Available Compliance Frameworks:"
    echo "=================================="
    
    if [[ -f "$CONFIG_DIR/compliance-frameworks.json" ]]; then
        node -e "
        const fs = require('fs');
        const config = JSON.parse(fs.readFileSync('$CONFIG_DIR/compliance-frameworks.json', 'utf8'));
        const frameworks = config.compliance_frameworks || {};
        
        Object.entries(frameworks).forEach(([name, framework]) => {
            const status = framework.enabled ? '✅' : '⚪';
            console.error(\`\${status} \${name.toUpperCase()}\`);
            console.error(\`   Name: \${framework.name}\`);
            console.error(\`   Version: \${framework.version}\`);
            console.error(\`   Status: \${framework.enabled ? 'Enabled' : 'Disabled'}\`);
            console.error('');
        });
        "
    else
        log_error "Compliance frameworks configuration not found!"
        exit 1
    fi
}

enable_framework() {
    local framework="$1"
    if [[ -z "$framework" ]]; then
        log_error "Framework name required"
        echo "Usage: $0 enable <framework_name>"
        return 1
    fi
    
    log_info "Enabling compliance framework: $framework"
    
    # Update configuration file
    node -e "
    const fs = require('fs');
    const configPath = '$CONFIG_DIR/compliance-frameworks.json';
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    
    if (config.compliance_frameworks && config.compliance_frameworks['$framework']) {
        config.compliance_frameworks['$framework'].enabled = true;
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        console.error('Framework $framework enabled successfully');
    } else {
        console.error('Framework $framework not found');
        process.exit(1);
    }
    "
    
    log_success "Framework $framework enabled"
}

disable_framework() {
    local framework="$1"
    if [[ -z "$framework" ]]; then
        log_error "Framework name required"
        echo "Usage: $0 disable <framework_name>"
        return 1
    fi
    
    log_info "Disabling compliance framework: $framework"
    
    node -e "
    const fs = require('fs');
    const configPath = '$CONFIG_DIR/compliance-frameworks.json';
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    
    if (config.compliance_frameworks && config.compliance_frameworks['$framework']) {
        config.compliance_frameworks['$framework'].enabled = false;
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        console.error('Framework $framework disabled successfully');
    } else {
        console.error('Framework $framework not found');
        process.exit(1);
    }
    "
    
    log_success "Framework $framework disabled"
}

configure_industry() {
    local industry="$1"
    if [[ -z "$industry" ]]; then
        log_error "Industry type required"
        echo "Usage: $0 configure-industry <healthcare|finance|ecommerce|government|general>"
        return 1
    fi
    
    log_info "Configuring compliance frameworks for industry: $industry"
    
    # Update environment file
    if [[ -f ".env" ]]; then
        sed -i.bak "s/ORGANIZATION_INDUSTRY=.*/ORGANIZATION_INDUSTRY=$industry/" .env
    else
        echo "ORGANIZATION_INDUSTRY=$industry" >> .env
    fi
    
    # Enable industry-specific frameworks
    case "$industry" in
        "healthcare")
            enable_framework "hipaa"
            enable_framework "nist_csf"
            log_info "Enabled HIPAA and NIST CSF for healthcare industry"
            ;;
        "finance")
            enable_framework "pci_dss"
            enable_framework "sox"
            enable_framework "nist_csf"
            log_info "Enabled PCI DSS, SOX, and NIST CSF for finance industry"
            ;;
        "ecommerce")
            enable_framework "pci_dss"
            enable_framework "gdpr"
            enable_framework "ccpa"
            log_info "Enabled PCI DSS, GDPR, and CCPA for ecommerce industry"
            ;;
        "government")
            enable_framework "fisma"
            enable_framework "fedramp"
            enable_framework "nist_csf"
            log_info "Enabled FISMA, FedRAMP, and NIST CSF for government industry"
            ;;
        "general")
            enable_framework "nist_csf"
            enable_framework "iso27001"
            log_info "Enabled NIST CSF and ISO 27001 for general industry"
            ;;
        *)
            log_error "Unknown industry type: $industry"
            return 1
            ;;
    esac
    
    log_success "Industry configuration completed for: $industry"
}

# ===========================================
# Scanning Functions
# ===========================================

compliance_scan() {
    local scan_path="$1"
    local frameworks="$2"
    local format="${3:-html}"
    
    if [[ -z "$scan_path" ]]; then
        scan_path="."
    fi
    
    log_info "Starting compliance scan..."
    log_info "Path: $scan_path"
    log_info "Format: $format"
    
    if [[ -n "$frameworks" ]]; then
        log_info "Frameworks: $frameworks"
    else
        log_info "Frameworks: All enabled frameworks"
    fi
    
    # Run the compliance scan via MCP server
    if [[ -f "server.js" ]]; then
        if [[ -n "$frameworks" ]]; then
            node server.js compliance_scan "$scan_path" --frameworks="$frameworks" --format="$format"
        else
            node server.js compliance_scan "$scan_path" --format="$format"
        fi
    else
        log_error "Server.js not found. Make sure you're in the project directory."
        return 1
    fi
    
    log_success "Compliance scan completed"
    log_info "Reports saved to: $REPORTS_DIR"
}

quick_scan() {
    local scan_path="${1:-.}"
    log_info "Running quick compliance scan on: $scan_path"
    compliance_scan "$scan_path" "" "json"
}

# ===========================================
# Reporting Functions
# ===========================================

generate_report() {
    local scan_path="$1"
    local format="${2:-html}"
    local frameworks="$3"
    
    if [[ -z "$scan_path" ]]; then
        log_error "Scan path required"
        echo "Usage: $0 report <scan_path> [format] [frameworks]"
        return 1
    fi
    
    log_info "Generating compliance report..."
    log_info "Path: $scan_path"
    log_info "Format: $format"
    
    # Ensure reports directory exists
    mkdir -p "$REPORTS_DIR"
    
    # Generate report via MCP server
    if [[ -f "server.js" ]]; then
        if [[ -n "$frameworks" ]]; then
            node server.js generate_compliance_report "$scan_path" "$REPORTS_DIR" --frameworks="$frameworks" --format="$format"
        else
            node server.js generate_compliance_report "$scan_path" "$REPORTS_DIR" --format="$format"
        fi
    else
        log_error "Server.js not found"
        return 1
    fi
    
    log_success "Compliance report generated"
    log_info "Report saved to: $REPORTS_DIR"
}

# ===========================================
# Monitoring Functions
# ===========================================

start_monitoring() {
    local project_path="${1:-.}"
    local schedule="${2:-0 */6 * * *}"
    
    log_info "Starting continuous compliance monitoring..."
    log_info "Project: $project_path"
    log_info "Schedule: $schedule"
    
    if [[ -f "server.js" ]]; then
        node server.js start_continuous_monitoring "$project_path" --schedule="$schedule"
    else
        log_error "Server.js not found"
        return 1
    fi
    
    log_success "Compliance monitoring started"
}

check_status() {
    log_info "Compliance System Status:"
    echo "=========================="
    
    # Check configuration files
    if [[ -f "$CONFIG_DIR/compliance-frameworks.json" ]]; then
        log_success "Compliance frameworks configuration: Found"
    else
        log_error "Compliance frameworks configuration: Missing"
    fi
    
    if [[ -f "$CONFIG_DIR/compliance-settings.json" ]]; then
        log_success "Compliance settings configuration: Found"
    else
        log_error "Compliance settings configuration: Missing"
    fi
    
    # Check enabled frameworks
    if [[ -f "$CONFIG_DIR/compliance-frameworks.json" ]]; then
        local enabled_count=$(node -e "
        const fs = require('fs');
        const config = JSON.parse(fs.readFileSync('$CONFIG_DIR/compliance-frameworks.json', 'utf8'));
        const frameworks = config.compliance_frameworks || {};
        const enabled = Object.values(frameworks).filter(f => f.enabled).length;
        console.error(enabled);
        ")
        log_info "Enabled frameworks: $enabled_count"
    fi
    
    # Check report directory
    if [[ -d "$REPORTS_DIR" ]]; then
        local report_count=$(find "$REPORTS_DIR" -name "*.html" -o -name "*.json" -o -name "*.md" | wc -l)
        log_info "Generated reports: $report_count"
    fi
    
    # Check Docker status
    if command -v docker &> /dev/null; then
        if docker ps | grep -q spotter-sast; then
            log_success "Docker container: Running"
        else
            log_warning "Docker container: Not running"
        fi
    fi
}

# ===========================================
# Utility Functions
# ===========================================

validate_config() {
    log_info "Validating compliance configuration..."
    
    local errors=0
    
    # Check required configuration files
    local required_files=(
        "$CONFIG_DIR/compliance-frameworks.json"
        "$CONFIG_DIR/compliance-settings.json"
        "$CONFIG_DIR/custom-compliance-rules.json"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_success "Found: $(basename "$file")"
            
            # Validate JSON syntax
            if ! node -e "JSON.parse(require('fs').readFileSync('$file', 'utf8'))" 2>/dev/null; then
                log_error "Invalid JSON in: $(basename "$file")"
                ((errors++))
            fi
        else
            log_error "Missing: $(basename "$file")"
            ((errors++))
        fi
    done
    
    # Check environment configuration
    if [[ -f ".env" ]]; then
        log_success "Found: .env file"
        
        # Check for required environment variables
        local required_vars=(
            "ORGANIZATION_INDUSTRY"
            "DEFAULT_COMPLIANCE_FRAMEWORKS"
        )
        
        for var in "${required_vars[@]}"; do
            if grep -q "^$var=" .env; then
                log_success "Environment variable: $var"
            else
                log_warning "Missing environment variable: $var"
            fi
        done
    else
        log_warning "Environment file (.env) not found"
        log_info "Consider copying from .env.example"
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "Configuration validation passed"
    else
        log_error "Configuration validation failed with $errors errors"
        return 1
    fi
}

setup_compliance() {
    log_info "Setting up compliance system..."
    
    # Create required directories
    mkdir -p "$CONFIG_DIR" "$REPORTS_DIR" "$EVIDENCE_DIR" "logs"
    
    # Copy example configuration files if they don't exist
    if [[ ! -f ".env" && -f ".env.example" ]]; then
        cp ".env.example" ".env"
        log_success "Created .env from .env.example"
    fi
    
    # Set default industry if not specified
    if [[ -f ".env" ]] && ! grep -q "ORGANIZATION_INDUSTRY" .env; then
        echo "ORGANIZATION_INDUSTRY=general" >> .env
        log_info "Set default industry to 'general'"
    fi
    
    # Validate setup
    validate_config
    
    log_success "Compliance system setup completed"
    log_info "Next steps:"
    log_info "1. Configure your industry: $0 configure-industry <industry>"
    log_info "2. Run a compliance scan: $0 scan <path>"
    log_info "3. Generate a report: $0 report <path>"
}

# ===========================================
# Main Script Logic
# ===========================================

show_help() {
    echo "🛡️ Spotter-SAST Compliance Management"
    echo "====================================="
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Framework Management:"
    echo "  list                          - List all available frameworks"
    echo "  enable <framework>            - Enable a specific framework"
    echo "  disable <framework>           - Disable a specific framework"
    echo "  configure-industry <industry> - Configure frameworks for industry type"
    echo ""
    echo "Scanning & Analysis:"
    echo "  scan [path] [frameworks] [format]     - Run compliance scan"
    echo "  quick-scan [path]                      - Run quick compliance scan"
    echo "  report <path> [format] [frameworks]   - Generate compliance report"
    echo ""
    echo "Monitoring:"
    echo "  start-monitoring [path] [schedule]     - Start continuous monitoring"
    echo "  status                                 - Show system status"
    echo ""
    echo "Configuration:"
    echo "  setup                         - Setup compliance system"
    echo "  validate                      - Validate configuration"
    echo ""
    echo "Industry Types:"
    echo "  healthcare, finance, ecommerce, government, general"
    echo ""
    echo "Report Formats:"
    echo "  html, json, markdown, sarif"
    echo ""
    echo "Framework Names:"
    echo "  hipaa, gdpr, pci_dss, iso27001, sox, nist_csf, ccpa, fisma, fedramp"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 configure-industry healthcare"
    echo "  $0 scan ./src hipaa,gdpr html"
    echo "  $0 report ./project html"
    echo "  $0 start-monitoring ./project '0 */6 * * *'"
    echo ""
}

# Main command processing
case "${1:-help}" in
    "list"|"list-frameworks")
        list_frameworks
        ;;
    "enable")
        enable_framework "$2"
        ;;
    "disable")
        disable_framework "$2"
        ;;
    "configure-industry")
        configure_industry "$2"
        ;;
    "scan")
        compliance_scan "$2" "$3" "$4"
        ;;
    "quick-scan")
        quick_scan "$2"
        ;;
    "report")
        generate_report "$2" "$3" "$4"
        ;;
    "start-monitoring")
        start_monitoring "$2" "$3"
        ;;
    "status")
        check_status
        ;;
    "setup")
        setup_compliance
        ;;
    "validate")
        validate_config
        ;;
    "help"|*)
        show_help
        ;;
esac