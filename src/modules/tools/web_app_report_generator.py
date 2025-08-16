#!/usr/bin/env python3
"""
Web Application Security Assessment Report Generator

This tool generates comprehensive professional security assessment reports
from evidence collected during web application testing. It produces 
industry-standard reports following the structured template format.

Key Features:
- Professional markdown report generation
- Evidence aggregation from memory
- Phase-based organization
- Executive summary generation
- OWASP/CWE mapping integration
- Artifact management and indexing
"""

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import defaultdict, Counter

from strands import tool

logger = logging.getLogger(__name__)

# Severity mapping for prioritization
SEVERITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5
}

# Phase mapping for organization
PHASE_NAMES = {
    "P1-Discovery": "Discovery (Information Gathering)",
    "P2-Configuration": "Configuration & Deployment",
    "P3-Authentication": "Identity Management & Authentication",
    "P4-Authorization": "Authorization",
    "P5-Session": "Session Management & Cryptography",
    "P6-Validation": "Data Validation (Input Validation)",
    "P7-ErrorHandling": "Error Handling",
    "P8-DataProtection": "Data Protection",
    "BusinessLogic": "Business Logic Testing"
}


def parse_memory_content(content: str, metadata: Dict) -> Dict:
    """Parse memory content into structured finding data."""
    try:
        # Extract test_id and observation from content
        if content.startswith("[") and "]" in content:
            test_id_end = content.find("]")
            test_id = content[1:test_id_end]
            remaining = content[test_id_end + 1:].strip()
            
            if ":" in remaining and " - Evidence:" in remaining:
                phase_obs = remaining.split(" - Evidence:", 1)
                phase_observation = phase_obs[0].strip()
                evidence = phase_obs[1].strip() if len(phase_obs) > 1 else ""
                
                # Parse phase from observation
                if ":" in phase_observation:
                    phase, observation = phase_observation.split(":", 1)
                    phase = phase.strip()
                    observation = observation.strip()
                else:
                    phase = metadata.get("phase", "Unknown")
                    observation = phase_observation
            else:
                phase = metadata.get("phase", "Unknown")
                observation = remaining
                evidence = ""
        else:
            test_id = metadata.get("test_id", "Unknown")
            phase = metadata.get("phase", "Unknown")
            observation = content
            evidence = ""
        
        return {
            "test_id": test_id,
            "phase": phase,
            "observation": observation,
            "evidence": evidence,
            "severity": metadata.get("severity", "info"),
            "endpoint": metadata.get("endpoint", ""),
            "auth_context": metadata.get("auth_context", "none"),
            "result": metadata.get("result", "unknown"),
            "mappings": metadata.get("mappings", {"OWASP": [], "CWE": []}),
            "metadata": metadata
        }
    except Exception as e:
        logger.error("Failed to parse memory content: %s", e)
        return {
            "test_id": "PARSE-ERROR",
            "phase": "Unknown",
            "observation": content[:100],
            "evidence": str(e),
            "severity": "info",
            "endpoint": "",
            "auth_context": "none",
            "result": "error",
            "mappings": {"OWASP": [], "CWE": []},
            "metadata": metadata
        }


def generate_finding_id(index: int) -> str:
    """Generate finding ID in format F-001, F-002, etc."""
    return f"F-{index:03d}"


def format_phase_summary(phase: str, findings: List[Dict], deliverables: List[Dict]) -> str:
    """Format a phase summary section."""
    phase_name = PHASE_NAMES.get(phase, phase)
    
    # Count findings by result
    total_tests = len(findings)
    vulnerabilities = [f for f in findings if f["result"] == "vuln"]
    passes = [f for f in findings if f["result"] == "pass"]
    failures = [f for f in findings if f["result"] == "fail"]
    
    # Status determination
    if vulnerabilities:
        status = "⚠️ Issues Found"
    elif failures:
        status = "⚠️ Partial"
    elif passes:
        status = "✅ Complete"
    else:
        status = "❌ N/A"
    
    summary = f"""**{phase_name}**
• Status: {status}
• Tests Executed: {total_tests}
• Vulnerabilities Found: {len(vulnerabilities)}
• Highlights: """
    
    if vulnerabilities:
        vuln_highlights = [f["observation"][:60] + "..." for f in vulnerabilities[:2]]
        summary += ", ".join(vuln_highlights)
    else:
        summary += "No significant security issues identified"
    
    if deliverables:
        deliverable_types = [d.get("deliverable_type", "unknown") for d in deliverables]
        summary += f"\n• Artifacts: {', '.join(set(deliverable_types))}"
    
    return summary + "\n"


def generate_executive_summary(findings: List[Dict], total_tests: int) -> str:
    """Generate executive summary with top findings."""
    vulnerabilities = [f for f in findings if f["result"] == "vuln"]
    
    # Count by severity
    severity_counts = Counter(f["severity"] for f in vulnerabilities)
    
    # Risk posture assessment
    if severity_counts.get("critical", 0) > 0:
        risk_posture = "🔴 **High Risk**"
    elif severity_counts.get("high", 0) > 0:
        risk_posture = "🟡 **Medium Risk**"
    elif severity_counts.get("medium", 0) > 0:
        risk_posture = "🟢 **Low-Medium Risk**"
    else:
        risk_posture = "🟢 **Low Risk**"
    
    # Top 5 findings
    top_findings = sorted(vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))[:5]
    
    summary = f"""## Executive Summary

**Risk Posture**: {risk_posture}

**Vulnerability Summary**:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}

**Testing Coverage**: {total_tests} security tests executed across all phases

### Top Security Findings

| Rank | Finding | Severity | Phase |
|------|---------|----------|-------|"""
    
    for i, finding in enumerate(top_findings, 1):
        phase_short = finding["phase"].replace("-", " ")
        observation_short = finding["observation"][:50] + "..." if len(finding["observation"]) > 50 else finding["observation"]
        summary += f"\n| {i} | {observation_short} | {finding['severity'].title()} | {phase_short} |"
    
    if not top_findings:
        summary += "\n| - | No vulnerabilities found | - | - |"
    
    # Key strengths and recommendations
    summary += f"""

### Key Strengths
- Structured security testing methodology applied
- Comprehensive coverage across {len(set(f['phase'] for f in findings))} security domains
- Automated evidence collection and documentation

### Quick Wins (Immediate Actions)
"""
    
    # Generate quick wins from medium/high findings
    quick_wins = [f for f in vulnerabilities if f["severity"] in ["high", "medium"]][:3]
    if quick_wins:
        for i, finding in enumerate(quick_wins, 1):
            summary += f"{i}. Address {finding['observation'].lower()}\n"
    else:
        summary += "1. Maintain current security posture\n2. Regular security assessments\n3. Security awareness training\n"
    
    return summary


@tool
def web_app_report_generator(
    engagement_name: str,
    client_org: str,
    app_name: str,
    tester_name: str,
    output_format: str = "markdown",
    include_appendices: bool = True,
    filter_severity: Optional[str] = None
) -> str:
    """
    Generate comprehensive web application security assessment report.
    
    This tool pulls evidence and findings from memory to create a professional
    security assessment report following industry standards and best practices.
    
    Args:
        engagement_name: Name of the security engagement
        client_org: Client organization name
        app_name: Application name being assessed
        tester_name: Name of the security tester/team
        output_format: Report format (default: markdown)
        include_appendices: Include detailed appendices (default: True)
        filter_severity: Filter findings by severity level (optional)
        
    Returns:
        Generated security assessment report
    """
    # Import available tools
    try:
        from strands import get_available_tools
        available_tools = get_available_tools()
        
        mem0_memory = None
        for tool_name, tool_func in available_tools.items():
            if tool_name == "mem0_memory":
                mem0_memory = tool_func
                break
                
        if not mem0_memory:
            return "Error: mem0_memory tool not available for report generation"
            
    except Exception as e:
        return f"Error accessing memory tool: {e}"
    
    print(f"📊 Generating Web Application Security Assessment Report")
    print(f"   Engagement: {engagement_name}")
    print(f"   Application: {app_name}")
    print(f"   Format: {output_format}")
    
    try:
        # Retrieve all webapp findings from memory
        print("   📝 Retrieving findings from memory...")
        
        findings_response = mem0_memory(
            action="list",
            user_id="cyber_agent"
        )
        
        # Parse the memory response
        if isinstance(findings_response, str):
            try:
                findings_data = json.loads(findings_response)
            except json.JSONDecodeError:
                findings_data = []
        else:
            findings_data = findings_response if isinstance(findings_response, list) else []
        
        # Filter for webapp-related memories
        webapp_findings = []
        webapp_deliverables = []
        
        for memory_item in findings_data:
            metadata = memory_item.get("metadata", {})
            category = metadata.get("category", "")
            
            if category == "webapp_finding":
                parsed_finding = parse_memory_content(
                    memory_item.get("memory", ""), metadata
                )
                webapp_findings.append(parsed_finding)
            elif category == "webapp_deliverable":
                webapp_deliverables.append(memory_item)
        
        print(f"   📊 Found {len(webapp_findings)} findings and {len(webapp_deliverables)} deliverables")
        
        # Filter by severity if specified
        if filter_severity:
            webapp_findings = [f for f in webapp_findings if f["severity"] == filter_severity.lower()]
            print(f"   🔍 Filtered to {len(webapp_findings)} {filter_severity} severity findings")
        
        # Organize findings by phase
        findings_by_phase = defaultdict(list)
        for finding in webapp_findings:
            findings_by_phase[finding["phase"]].append(finding)
        
        # Organize deliverables by phase
        deliverables_by_phase = defaultdict(list)
        for deliverable in webapp_deliverables:
            phase = deliverable.get("metadata", {}).get("phase", "Unknown")
            deliverables_by_phase[phase].append(deliverable)
        
        # Generate report timestamp
        report_date = datetime.now().strftime("%Y-%m-%d")
        report_time = datetime.now().strftime("%H:%M:%S")
        
        # Start building the report
        report = f"""# Web Application Security Assessment Report

## Report Metadata
- **Engagement**: {engagement_name}
- **Client/Organization**: {client_org}
- **Application**: {app_name}
- **Assessment Date**: {report_date}
- **Report Generated**: {report_date} {report_time}
- **Tester**: {tester_name}
- **Methodology**: OWASP-based 8-Phase Security Testing
- **Report Version**: v1.0

---

"""
        
        # Executive Summary
        report += generate_executive_summary(webapp_findings, len(webapp_findings))
        report += "\n\n---\n\n"
        
        # Coverage & Methodology
        phases_tested = list(findings_by_phase.keys())
        report += f"""## Coverage & Methodology

**Overall Coverage**:
- Phases Executed: {len(phases_tested)}
- Total Security Tests: {len(webapp_findings)}
- Evidence Items Collected: {len(webapp_findings) + len(webapp_deliverables)}

**Methodology**: This assessment followed an 8-phase structured security testing methodology based on OWASP guidelines:

1. Discovery (Information Gathering)
2. Configuration & Deployment Security
3. Identity Management & Authentication
4. Authorization Controls
5. Session Management & Cryptography
6. Data Validation (Input Security)
7. Error Handling
8. Data Protection

**Testing Approach**: Automated security testing with manual validation, evidence-based findings, and structured documentation.

---

"""
        
        # Phase Summaries
        report += "## Phase Summaries\n\n"
        
        for phase in ["P1-Discovery", "P2-Configuration", "P3-Authentication", 
                     "P4-Authorization", "P5-Session", "P6-Validation", 
                     "P7-ErrorHandling", "P8-DataProtection", "BusinessLogic"]:
            if phase in findings_by_phase or phase in deliverables_by_phase:
                phase_findings = findings_by_phase.get(phase, [])
                phase_deliverables = deliverables_by_phase.get(phase, [])
                report += format_phase_summary(phase, phase_findings, phase_deliverables)
        
        report += "\n---\n\n"
        
        # Consolidated Findings Table
        vulnerabilities = [f for f in webapp_findings if f["result"] == "vuln"]
        vulnerabilities.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        
        report += "## Security Findings Summary\n\n"
        
        if vulnerabilities:
            report += "| ID | Finding | Phase | Severity | Status |\n"
            report += "|----|---------|---------|-----------|---------|\n"
            
            for i, finding in enumerate(vulnerabilities, 1):
                finding_id = generate_finding_id(i)
                phase_short = finding["phase"].replace("-", " ")
                observation_short = finding["observation"][:60] + "..." if len(finding["observation"]) > 60 else finding["observation"]
                report += f"| {finding_id} | {observation_short} | {phase_short} | {finding['severity'].title()} | Confirmed |\n"
        else:
            report += "✅ **No security vulnerabilities identified during assessment.**\n"
        
        report += "\n---\n\n"
        
        # Detailed Finding Records
        if vulnerabilities:
            report += "## Detailed Security Findings\n\n"
            
            for i, finding in enumerate(vulnerabilities, 1):
                finding_id = generate_finding_id(i)
                phase_name = PHASE_NAMES.get(finding["phase"], finding["phase"])
                
                # Map OWASP/CWE
                mappings = finding.get("mappings", {"OWASP": [], "CWE": []})
                owasp_list = ", ".join(mappings.get("OWASP", [])) or "Not mapped"
                cwe_list = ", ".join(mappings.get("CWE", [])) or "Not mapped"
                
                report += f"""### {finding_id} — {finding['observation']} ({finding['severity'].title()})

**Phase**: {phase_name}  
**Endpoint**: `{finding['endpoint']}`  
**Auth Context**: {finding['auth_context']}  

**Description**: {finding['observation']}

**Evidence**:
```
{finding['evidence'][:500]}{'...' if len(finding['evidence']) > 500 else ''}
```

**Impact**: Security vulnerability identified that requires remediation.

**Severity**: {finding['severity'].title()}

**OWASP Mapping**: {owasp_list}  
**CWE Mapping**: {cwe_list}

**Remediation**: Review and address the identified security issue according to security best practices.

**Status**: Confirmed  
**Test ID**: {finding['test_id']}

---

"""
        
        # Evidence Log
        report += "## Evidence Log\n\n"
        report += "| Test ID | Phase | Endpoint | Result | Severity | Observation |\n"
        report += "|---------|-------|----------|--------|----------|--------------|\n"
        
        for finding in webapp_findings:
            endpoint_short = finding['endpoint'][:30] + "..." if len(finding['endpoint']) > 30 else finding['endpoint']
            observation_short = finding['observation'][:40] + "..." if len(finding['observation']) > 40 else finding['observation']
            report += f"| {finding['test_id']} | {finding['phase']} | {endpoint_short} | {finding['result']} | {finding['severity']} | {observation_short} |\n"
        
        if include_appendices:
            report += "\n---\n\n"
            report += "## Recommendations\n\n"
            
            if vulnerabilities:
                severity_groups = defaultdict(list)
                for vuln in vulnerabilities:
                    severity_groups[vuln["severity"]].append(vuln)
                
                for severity in ["critical", "high", "medium", "low"]:
                    if severity in severity_groups:
                        report += f"### {severity.title()} Priority\n"
                        for vuln in severity_groups[severity]:
                            report += f"- Address {vuln['observation'].lower()}\n"
                        report += "\n"
            else:
                report += """### Security Posture Maintenance
- Continue regular security assessments
- Implement security monitoring
- Maintain security awareness training
- Keep security frameworks up to date

"""
            
            # Security Hardening Checklist
            report += """### General Security Hardening Checklist
- ✅ **Headers**: Implement security headers (CSP, HSTS, X-Frame-Options)
- ✅ **TLS**: Use strong TLS configuration and HTTPS enforcement
- ✅ **Authentication**: Implement strong authentication and MFA
- ✅ **Authorization**: Enforce proper access controls and RBAC
- ✅ **Session**: Secure session management and token handling
- ✅ **Input Validation**: Implement comprehensive input validation
- ✅ **Error Handling**: Use generic error messages and proper logging
- ✅ **Data Protection**: Protect sensitive data in transit and at rest

"""
        
        # Report Footer
        report += f"""---

## Report Completion

**Assessment Completed**: {report_date} {report_time}  
**Total Findings**: {len(vulnerabilities)} vulnerabilities, {len(webapp_findings) - len(vulnerabilities)} informational  
**Generated By**: {tester_name}  
**Report Format**: {output_format.title()}

*This report was generated automatically from structured security testing evidence.*

---

**End of Report**
"""
        
        print(f"   ✅ Report generation completed")
        print(f"   📊 Report contains {len(vulnerabilities)} findings across {len(phases_tested)} phases")
        
        return report
        
    except Exception as e:
        error_msg = f"Report generation failed: {str(e)}"
        print(f"   ❌ {error_msg}")
        logger.error("Report generation error: %s", e)
        return error_msg
