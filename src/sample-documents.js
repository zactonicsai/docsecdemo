/**
 * Sample Documents for OpenSearch
 * 
 * These documents demonstrate cell-level access control with various
 * security classifications and sensitive fields.
 */

const { v4: uuidv4 } = require('uuid');

const sampleDocuments = [
  // ==========================================
  // ENGINEERING DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'System Architecture Overview',
    type: 'technical',
    department: 'engineering',
    classification: 'internal',
    sensitivity: 'low',
    author: 'Alice Chen',
    summary: 'High-level overview of our microservices architecture including service mesh, API gateway, and database layer.',
    content: `
# System Architecture Overview

## Introduction
Our platform is built on a modern microservices architecture designed for scalability, resilience, and maintainability.

## Core Components

### API Gateway
The API gateway handles all incoming requests, performing:
- Authentication and authorization
- Rate limiting
- Request routing
- Load balancing

### Service Mesh
We use Istio as our service mesh, providing:
- Service discovery
- Traffic management
- Security (mTLS)
- Observability

### Database Layer
- PostgreSQL for transactional data
- Redis for caching
- Elasticsearch for search
- MongoDB for document storage

## Deployment
All services are containerized with Docker and orchestrated via Kubernetes.
    `.trim(),
    confidential_notes: 'AWS account ID: 123456789012. Primary region: us-east-1. Backup region: eu-west-1.',
    internal_comments: 'Need to review security group configurations before Q2 audit.',
    tags: ['architecture', 'microservices', 'kubernetes', 'infrastructure']
  },

  {
    id: uuidv4(),
    title: 'Database Migration Guide - Q4 2024',
    type: 'technical',
    department: 'engineering',
    classification: 'confidential',
    sensitivity: 'medium',
    author: 'Bob Martinez',
    summary: 'Step-by-step guide for migrating from PostgreSQL 12 to PostgreSQL 15 with zero downtime.',
    content: `
# Database Migration Guide

## Overview
This guide covers the migration of our production PostgreSQL database from version 12 to 15.

## Pre-Migration Checklist
1. Backup verification
2. Replication lag monitoring
3. Application compatibility testing
4. Rollback procedure review

## Migration Steps

### Phase 1: Preparation
- Set up PostgreSQL 15 replica
- Configure logical replication
- Verify data consistency

### Phase 2: Cutover
- Stop write traffic
- Wait for replication sync
- Switch DNS
- Verify application connectivity

### Phase 3: Cleanup
- Decommission old primary
- Update monitoring
- Document lessons learned

## Rollback Procedure
In case of issues, immediately execute rollback-prod.sh
    `.trim(),
    confidential_notes: 'Database credentials stored in Vault path: secret/prod/postgres. Master password last rotated: 2024-01-15.',
    internal_comments: 'Estimated downtime during cutover: 30 seconds. Approved by CTO on 2024-01-10.',
    financial_data: 'Migration budget: $45,000. AWS costs increase estimated at $2,500/month post-migration.',
    tags: ['database', 'postgresql', 'migration', 'production']
  },

  {
    id: uuidv4(),
    title: 'Security Incident Response Playbook',
    type: 'security',
    department: 'engineering',
    classification: 'restricted',
    sensitivity: 'high',
    author: 'Security Team',
    summary: 'Procedures for responding to security incidents including data breaches, unauthorized access, and malware.',
    content: `
# Security Incident Response Playbook

## Incident Classification

### Severity Levels
- P1 (Critical): Active data breach, system compromise
- P2 (High): Suspected breach, significant vulnerability
- P3 (Medium): Policy violation, minor vulnerability
- P4 (Low): Security awareness issue

## Response Procedures

### Initial Response (0-15 minutes)
1. Confirm incident is real
2. Classify severity
3. Notify on-call security engineer
4. Begin evidence preservation

### Containment (15-60 minutes)
1. Isolate affected systems
2. Block malicious IPs/accounts
3. Preserve forensic evidence
4. Notify stakeholders

### Eradication and Recovery
1. Remove threat actors
2. Patch vulnerabilities
3. Restore from clean backups
4. Verify system integrity

## Communication Templates
See Appendix A for customer notification templates.
    `.trim(),
    confidential_notes: 'Emergency contacts: CISO cell: 555-0100, Legal: 555-0101, PR: 555-0102. FBI liaison: Agent Smith, 555-0103.',
    internal_comments: 'Last tabletop exercise: 2024-01-05. Next scheduled: 2024-04-05. Gaps identified in cloud forensics capability.',
    pii_data: 'Previous incident affected users: john.doe@email.com, jane.smith@email.com (notified per breach protocol).',
    tags: ['security', 'incident-response', 'playbook', 'critical']
  },

  // ==========================================
  // FINANCE DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'Q4 2024 Financial Report',
    type: 'financial',
    department: 'finance',
    classification: 'confidential',
    sensitivity: 'high',
    author: 'Finance Team',
    summary: 'Quarterly financial results including revenue, expenses, and profitability metrics.',
    content: `
# Q4 2024 Financial Report

## Executive Summary
Q4 showed strong performance with revenue exceeding targets by 12%.

## Key Metrics
- Total Revenue: Growth over previous quarter
- Operating Expenses: Within budget
- Net Income: Improved margin

## Revenue Breakdown
- Product Sales: 65%
- Services: 25%
- Licensing: 10%

## Outlook
Q1 2025 projected to continue growth trajectory with new product launches.
    `.trim(),
    confidential_notes: 'Board meeting scheduled for Jan 20 to discuss acquisition target valuation.',
    internal_comments: 'Auditor concerns about revenue recognition timing - addressed in footnotes.',
    financial_data: 'Total Revenue: $47.3M. Net Income: $8.2M. EBITDA: $12.1M. Cash on hand: $23.5M.',
    tags: ['finance', 'quarterly-report', 'revenue', 'confidential']
  },

  {
    id: uuidv4(),
    title: 'Employee Compensation Guidelines 2024',
    type: 'policy',
    department: 'finance',
    classification: 'internal',
    sensitivity: 'high',
    author: 'HR & Finance',
    summary: 'Guidelines for salary bands, bonus structures, and equity compensation across all departments.',
    content: `
# Employee Compensation Guidelines 2024

## Philosophy
Our compensation philosophy is to pay at the 75th percentile of market rates.

## Salary Bands

### Engineering
- Junior (L1-L2): Market competitive
- Senior (L3-L4): Market competitive
- Staff+ (L5+): Market competitive

### Sales
- Base + Commission structure
- OTE varies by role and territory

## Bonus Structure
- Target bonus: 10-30% of base salary
- Company performance modifier: 0.5x - 2.0x
- Individual performance modifier: 0.0x - 1.5x

## Equity Compensation
- Initial grants based on level
- Annual refresh grants
- 4-year vesting with 1-year cliff
    `.trim(),
    confidential_notes: 'Executive compensation: CEO base $450K + $900K bonus target. CFO base $350K + $525K bonus target.',
    internal_comments: 'Compensation committee approved 5% overall budget increase for 2024.',
    financial_data: 'Total compensation budget: $28.5M. Equity pool: 2.5M shares. Average raise: 4.2%.',
    pii_data: 'Top earners: Employee IDs 1001, 1002, 1003. Salary details in restricted appendix.',
    tags: ['hr', 'compensation', 'salary', 'policy']
  },

  // ==========================================
  // HR DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'Employee Handbook 2024',
    type: 'policy',
    department: 'hr',
    classification: 'public',
    sensitivity: 'low',
    author: 'HR Department',
    summary: 'Company policies, benefits information, and employee guidelines.',
    content: `
# Employee Handbook 2024

## Welcome
Welcome to the team! This handbook outlines our policies and your benefits.

## Work Environment
- Hybrid work policy (3 days in office)
- Core hours: 10am - 4pm
- Flexible scheduling available

## Benefits Overview
- Health insurance (medical, dental, vision)
- 401(k) with company match
- Unlimited PTO (minimum 15 days)
- Parental leave (16 weeks)
- Learning & development budget

## Code of Conduct
- Treat all colleagues with respect
- Report harassment or discrimination
- Maintain confidentiality
- Avoid conflicts of interest

## IT & Security
- Use strong passwords
- Enable MFA on all accounts
- Report suspicious emails
- Don't share credentials
    `.trim(),
    internal_comments: 'Legal reviewed on 2024-01-01. Update non-compete clause for California employees.',
    tags: ['hr', 'policy', 'handbook', 'onboarding']
  },

  {
    id: uuidv4(),
    title: 'Performance Review Process Guide',
    type: 'policy',
    department: 'hr',
    classification: 'internal',
    sensitivity: 'medium',
    author: 'HR Department',
    summary: 'Guidelines for conducting performance reviews, calibration, and promotion decisions.',
    content: `
# Performance Review Process

## Review Cycle
- Mid-year check-in: July
- Annual review: December
- Calibration: January
- Compensation decisions: February

## Rating Scale
1. Does not meet expectations
2. Partially meets expectations
3. Meets expectations
4. Exceeds expectations
5. Significantly exceeds expectations

## Manager Responsibilities
1. Gather peer feedback
2. Review goals and achievements
3. Write assessment
4. Deliver feedback in 1:1
5. Create development plan

## Calibration Process
- Department-level calibration
- Cross-functional review
- Executive approval for promotions
    `.trim(),
    confidential_notes: 'Promotion budget for 2024: 8% of payroll. Target promotion rate: 15% of eligible employees.',
    internal_comments: 'Consider adding 360 feedback for manager roles. Pilot in Engineering first.',
    tags: ['hr', 'performance', 'review', 'management']
  },

  // ==========================================
  // PRODUCT DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'Product Roadmap 2024',
    type: 'strategy',
    department: 'product',
    classification: 'confidential',
    sensitivity: 'medium',
    author: 'Product Team',
    summary: 'Strategic product initiatives and feature roadmap for 2024.',
    content: `
# Product Roadmap 2024

## Vision
Become the leading platform for enterprise workflow automation.

## Q1 Initiatives
- AI-powered document processing
- Enhanced API capabilities
- Mobile app refresh

## Q2 Initiatives
- Integration marketplace
- Advanced analytics dashboard
- Compliance automation

## Q3 Initiatives
- Multi-language support
- Enterprise SSO improvements
- Workflow templates library

## Q4 Initiatives
- AI assistant (beta)
- Custom reporting
- Performance optimizations

## Success Metrics
- User adoption: +40%
- Customer satisfaction: NPS 50+
- Revenue impact: +25%
    `.trim(),
    confidential_notes: 'AI features depend on partnership with OpenAI. Contract renewal due March 2024.',
    internal_comments: 'Competitor analysis shows gap in mobile experience. Prioritize mobile app in Q1.',
    financial_data: 'Product development budget: $12M. Expected ROI: 3.2x within 18 months.',
    tags: ['product', 'roadmap', 'strategy', '2024']
  },

  {
    id: uuidv4(),
    title: 'Customer Research Report - Enterprise Segment',
    type: 'research',
    department: 'product',
    classification: 'internal',
    sensitivity: 'medium',
    author: 'UX Research',
    summary: 'Research findings from interviews with 50 enterprise customers on workflow automation needs.',
    content: `
# Customer Research Report

## Methodology
- 50 in-depth interviews
- 200 survey responses
- 10 site visits

## Key Findings

### Pain Points
1. Complex approval workflows (78%)
2. Lack of integration with existing tools (65%)
3. Poor mobile experience (52%)
4. Compliance tracking difficulties (48%)

### Feature Requests
1. AI-powered suggestions
2. Slack/Teams integration
3. Custom reporting
4. Audit trail improvements

### Competitive Analysis
- Competitor A: Strong in SMB
- Competitor B: Better mobile app
- Our advantage: Enterprise security features

## Recommendations
1. Prioritize integration marketplace
2. Improve mobile app
3. Add AI features for suggestions
    `.trim(),
    confidential_notes: 'Key accounts interviewed: Acme Corp, Globex Inc, Initech. Quotes available for marketing with approval.',
    pii_data: 'Interview participants: sarah.johnson@acme.com, mike.wilson@globex.com (consent forms on file).',
    tags: ['research', 'customer', 'enterprise', 'ux']
  },

  // ==========================================
  // LEGAL DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'Data Processing Agreement Template',
    type: 'legal',
    department: 'legal',
    classification: 'internal',
    sensitivity: 'low',
    author: 'Legal Team',
    summary: 'Standard DPA template for customer contracts ensuring GDPR and CCPA compliance.',
    content: `
# Data Processing Agreement

## Definitions
- "Data Controller" means the Customer
- "Data Processor" means the Company
- "Personal Data" as defined in GDPR

## Processing Terms
1. Process data only on documented instructions
2. Ensure personnel confidentiality
3. Implement appropriate security measures
4. Assist with data subject requests
5. Delete data upon termination

## Security Measures
- Encryption in transit and at rest
- Access controls
- Regular security assessments
- Incident response procedures

## Sub-processors
List of approved sub-processors in Appendix A.
Customer will be notified of changes.

## Audit Rights
Customer may audit compliance upon reasonable notice.
    `.trim(),
    internal_comments: 'Updated for California Consumer Privacy Act requirements in December 2023.',
    tags: ['legal', 'gdpr', 'privacy', 'compliance', 'dpa']
  },

  {
    id: uuidv4(),
    title: 'Intellectual Property Guidelines',
    type: 'policy',
    department: 'legal',
    classification: 'confidential',
    sensitivity: 'medium',
    author: 'Legal Team',
    summary: 'Guidelines for protecting company intellectual property and handling third-party IP.',
    content: `
# Intellectual Property Guidelines

## Company IP Protection

### Patents
- Report inventions to Legal within 30 days
- Document development with timestamps
- Don't publish without clearance

### Trade Secrets
- Use NDAs with all external parties
- Limit access to need-to-know
- Mark confidential materials

### Copyrights
- Company owns work product
- Don't use unlicensed content
- Properly attribute open source

## Third-Party IP

### Software Licensing
- Approved licenses: MIT, Apache 2.0, BSD
- Prohibited: GPL, AGPL (without approval)
- Track all dependencies

### Content Usage
- Verify rights before use
- Document permissions
- Respect attribution requirements
    `.trim(),
    confidential_notes: 'Pending patent applications: 3. Trade secret inventory: 47 items. Annual legal budget for IP: $850K.',
    internal_comments: 'Review open source policy with engineering - some projects may have licensing issues.',
    tags: ['legal', 'ip', 'patents', 'copyright', 'policy']
  },

  // ==========================================
  // SALES DOCUMENTS
  // ==========================================
  {
    id: uuidv4(),
    title: 'Enterprise Sales Playbook',
    type: 'sales',
    department: 'sales',
    classification: 'internal',
    sensitivity: 'medium',
    author: 'Sales Enablement',
    summary: 'Sales methodology, competitive positioning, and objection handling for enterprise deals.',
    content: `
# Enterprise Sales Playbook

## Sales Methodology
We use MEDDIC for enterprise qualification:
- Metrics
- Economic Buyer
- Decision Criteria
- Decision Process
- Identify Pain
- Champion

## Ideal Customer Profile
- 500+ employees
- $50M+ revenue
- Technology or financial services
- Digital transformation initiatives

## Competitive Positioning

### vs Competitor A
- We win on: Security, compliance, support
- They win on: Price, brand recognition
- Key differentiator: Enterprise SSO, audit logs

### vs Competitor B
- We win on: Ease of use, time to value
- They win on: Feature breadth
- Key differentiator: 90-day implementation guarantee

## Pricing Strategy
- Land: Departmental deployment
- Expand: Cross-functional workflows
- Upsell: Premium features, support tiers
    `.trim(),
    confidential_notes: 'Strategic accounts: Acme (potential $2M ARR), BigCorp (competitive situation with Competitor A).',
    internal_comments: 'Win rate improving: 32% in Q3 vs 28% in Q2. Focus on MEDDIC adoption.',
    financial_data: 'Average deal size: $185K ARR. Sales cycle: 90 days. CAC: $45K. LTV:CAC ratio: 4.1x.',
    tags: ['sales', 'enterprise', 'playbook', 'methodology']
  }
];

// Field security metadata (defines sensitivity of each field type)
const fieldSecurityDefaults = {
  title: 'low',
  summary: 'low',
  content: 'low',
  author: 'low',
  department: 'low',
  tags: 'low',
  classification: 'low',
  confidential_notes: 'high',
  internal_comments: 'medium',
  financial_data: 'high',
  pii_data: 'high'
};

// Apply field security to all documents
sampleDocuments.forEach(doc => {
  doc.field_security = { ...fieldSecurityDefaults };
});

module.exports = {
  sampleDocuments,
  fieldSecurityDefaults
};
