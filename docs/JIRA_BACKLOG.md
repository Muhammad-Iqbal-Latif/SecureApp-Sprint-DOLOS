# Jira Sprint Setup: DOLOS (manual import checklist)

Create Scrum project `DOLOS Security Sprint` and 7-day sprint. Use states To Do, In Progress, In Review, Done. **Jira issue keys below are planning placeholders**, not actual keys until created. Do not claim they exist in Jira before you enter them.

## Epic A: Security design and threat modeling
- DOLOS-01 | Story | Approve custom theme & architecture | PNE-01..10 | Due Day 1
- DOLOS-02 | Story | Elicit stakeholder needs and map CIA | PNE-01..10 | Day 1
- DOLOS-03 | Task | Context and Level-1 DFDs | Threat model | Day 2
- DOLOS-04 | Task | STRIDE for every DFD element | T-BOF..T-PIPE | Day 2
- DOLOS-05 | Task | Two attack trees, CVSS and risk register | all P1/P2 | Day 2

## Epic B: Vulnerability remediation and proof
- DOLOS-11 | Story | Memory-unsafe native event parser and bounded rewrite | PNE-04 | T-BOF | ASan test | Day 3
- DOLOS-12 | Story | Remove shell evaluation from incident investigation | PNE-03 | T-CMD | injection marker test | Day 3
- DOLOS-13 | Story | Object-level incident ownership checks | PNE-01 | T-IDOR | cross-user 404 | Day 4
- DOLOS-14 | Story | Synchronizer tokens for decoy updates | PNE-02 | T-CSRF | missing-token 403 | Day 4
- DOLOS-15 | Story | Stop sensitive page framing | PNE-05 | T-FRAME | CSP/XFO + iframe | Day 4
- DOLOS-16 | Story | Escape incident values and secure login | PNE-06/09 | T-XSS,T-AUTH | regression tests | Day 5

## Epic C: DevSecOps automation
- DOLOS-21 | Story | GitHub Actions with branch protections and reviews | PNE-08 | T-PIPE | approved PR screenshot | Day 5
- DOLOS-22 | Task | Bandit and security severity gates | PNE-08 | T-PIPE | red/green logs | Day 5
- DOLOS-23 | Task | OWASP ZAP DAST and JSON artifact | PNE-08 | T-PIPE | report + gate | Day 6
- DOLOS-24 | Task | Containerize, non-root deploy and Trivy bonus | PNE-08/10 | T-PIPE | Docker image + scan | Day 6

## Epic D: Final evidence and presentation
- DOLOS-30 | Story | Residual-risk review and exception decisions | all PNE | residual risks | Day 6
- DOLOS-31 | Task | 18-30-page IEEE-style report | all | PDF with screenshots | Day 7
- DOLOS-32 | Task | 6-10-minute demo recording | all | video/link | Day 7
- DOLOS-33 | Task | Export Jira sprint board and individual contributions | all | board screenshot | Day 7

For each Jira issue: include Owner, Acceptance Criteria, PNE ID, STRIDE threat, CVSS vector (when relevant), source commit/PR URL, test name and evidence file. The title IDs are examples; use Jira's actual project key when created.
