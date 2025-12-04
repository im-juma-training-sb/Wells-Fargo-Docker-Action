#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get inputs
SCAN_PATH="${INPUT_SCAN_PATH:-.}"
FAIL_ON_FINDINGS="${INPUT_FAIL_ON_FINDINGS:-true}"
SEVERITY_THRESHOLD="${INPUT_SEVERITY_THRESHOLD:-medium}"

echo "${BLUE}=== Wells Fargo Security Scanner ===${NC}"
echo "Scan Path: $SCAN_PATH"
echo "Fail on Findings: $FAIL_ON_FINDINGS"
echo "Severity Threshold: $SEVERITY_THRESHOLD"
echo ""

# Initialize counters
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Change to workspace directory
cd /github/workspace/$SCAN_PATH

# Create findings array
FINDINGS_FILE="/tmp/findings.txt"
> "$FINDINGS_FILE"

echo "${BLUE}Scanning for security issues...${NC}"
echo ""

# Read patterns from JSON
PATTERNS=$(jq -c '.patterns[]' /patterns.json)

# Scan files
while IFS= read -r pattern_obj; do
    NAME=$(echo "$pattern_obj" | jq -r '.name')
    PATTERN=$(echo "$pattern_obj" | jq -r '.pattern')
    SEVERITY=$(echo "$pattern_obj" | jq -r '.severity')
    DESCRIPTION=$(echo "$pattern_obj" | jq -r '.description')
    
    # Search for pattern (exclude .git directory and binary files)
    MATCHES=$(grep -r -n -E "$PATTERN" --exclude-dir=.git --exclude-dir=node_modules \
              --exclude="*.jpg" --exclude="*.png" --exclude="*.gif" --exclude="*.pdf" \
              . 2>/dev/null || true)
    
    if [ -n "$MATCHES" ]; then
        COUNT=$(echo "$MATCHES" | wc -l | tr -d ' ')
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
        
        case $SEVERITY in
            critical) CRITICAL_COUNT=$((CRITICAL_COUNT + COUNT)) ;;
            high) HIGH_COUNT=$((HIGH_COUNT + COUNT)) ;;
            medium) MEDIUM_COUNT=$((MEDIUM_COUNT + COUNT)) ;;
            low) LOW_COUNT=$((LOW_COUNT + COUNT)) ;;
        esac
        
        # Color based on severity
        case $SEVERITY in
            critical|high) COLOR=$RED ;;
            medium) COLOR=$YELLOW ;;
            *) COLOR=$NC ;;
        esac
        
        echo "${COLOR}[$SEVERITY] $NAME - $COUNT finding(s)${NC}"
        echo "$DESCRIPTION"
        echo "$MATCHES" | head -3
        echo ""
        
        # Save to findings file
        echo "[$SEVERITY] $NAME: $COUNT finding(s) - $DESCRIPTION" >> "$FINDINGS_FILE"
    fi
done <<< "$PATTERNS"

# Additional checks: Large files (potential data exfiltration)
echo "${BLUE}Checking for unusually large files...${NC}"
LARGE_FILES=$(find . -type f -size +10M -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
if [ -n "$LARGE_FILES" ]; then
    LARGE_COUNT=$(echo "$LARGE_FILES" | wc -l | tr -d ' ')
    echo "${YELLOW}[medium] Found $LARGE_COUNT file(s) larger than 10MB${NC}"
    echo "$LARGE_FILES" | head -3
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + LARGE_COUNT))
    MEDIUM_COUNT=$((MEDIUM_COUNT + LARGE_COUNT))
    echo ""
fi

# Check for common sensitive file names
echo "${BLUE}Checking for sensitive filenames...${NC}"
SENSITIVE_FILES=$(find . -type f \( -name "*.pem" -o -name "*.key" -o -name "*_rsa" \
                  -o -name "*.pfx" -o -name "*.p12" -o -name ".env" \
                  -o -name "credentials.*" -o -name "*secret*" \) \
                  -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
if [ -n "$SENSITIVE_FILES" ]; then
    SENSITIVE_COUNT=$(echo "$SENSITIVE_FILES" | wc -l | tr -d ' ')
    echo "${RED}[critical] Found $SENSITIVE_COUNT sensitive file(s)${NC}"
    echo "$SENSITIVE_FILES"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + SENSITIVE_COUNT))
    CRITICAL_COUNT=$((CRITICAL_COUNT + SENSITIVE_COUNT))
    echo ""
fi

# Generate summary
echo ""
echo "${BLUE}=== Scan Summary ===${NC}"
echo "Total Findings: $TOTAL_FINDINGS"
echo "  Critical: $CRITICAL_COUNT"
echo "  High: $HIGH_COUNT"
echo "  Medium: $MEDIUM_COUNT"
echo "  Low: $LOW_COUNT"
echo ""

# Set outputs
echo "findings-count=$TOTAL_FINDINGS" >> $GITHUB_OUTPUT
echo "critical-count=$CRITICAL_COUNT" >> $GITHUB_OUTPUT
echo "high-count=$HIGH_COUNT" >> $GITHUB_OUTPUT

# Determine scan status
SCAN_STATUS="passed"
if [ $TOTAL_FINDINGS -gt 0 ]; then
    case $SEVERITY_THRESHOLD in
        critical)
            [ $CRITICAL_COUNT -gt 0 ] && SCAN_STATUS="failed"
            ;;
        high)
            [ $((CRITICAL_COUNT + HIGH_COUNT)) -gt 0 ] && SCAN_STATUS="failed"
            ;;
        medium)
            [ $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT)) -gt 0 ] && SCAN_STATUS="failed"
            ;;
        low)
            [ $TOTAL_FINDINGS -gt 0 ] && SCAN_STATUS="failed"
            ;;
    esac
fi

echo "scan-status=$SCAN_STATUS" >> $GITHUB_OUTPUT

# Create GitHub job summary
cat << EOF >> $GITHUB_STEP_SUMMARY
## Security Scan Results

**Scan Path:** \`$SCAN_PATH\`  
**Status:** ${SCAN_STATUS^^}

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | $CRITICAL_COUNT |
| High | $HIGH_COUNT |
| Medium | $MEDIUM_COUNT |
| Low | $LOW_COUNT |
| **Total** | **$TOTAL_FINDINGS** |

### Recommendations

EOF

if [ $TOTAL_FINDINGS -eq 0 ]; then
    echo "No security issues detected. Great job!" >> $GITHUB_STEP_SUMMARY
    echo "${GREEN}Scan passed - No security issues found!${NC}"
    exit 0
else
    cat << EOF >> $GITHUB_STEP_SUMMARY

1. Review all detected security findings above
2. Remove any hardcoded credentials immediately
3. Use GitHub Secrets for sensitive values
4. Implement secret scanning in your repository settings
5. Consider using a secrets management system (HashiCorp Vault, AWS Secrets Manager)

Refer to Wells Fargo security guidelines for proper credential management.
EOF
    
    if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$SCAN_STATUS" = "failed" ]; then
        echo "${RED}Scan failed - Security issues detected!${NC}"
        exit 1
    else
        echo "${YELLOW}Security issues detected but not failing build${NC}"
        exit 0
    fi
fi
