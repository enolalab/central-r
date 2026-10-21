# Local Central Use Cases

Local Central should prioritize work that benefits from private data access, local tools, durable state, and long-running execution.

## Priority use cases

### Software development agent

- Analyze repositories and plan features
- Divide work among implementation, testing, and documentation agents
- Modify files, run builds, tests, and linters
- Resume repository-scale work after interruption
- Produce patches, reports, and test artifacts

### Private document research

- Analyze local PDF, Markdown, source code, reports, contracts, and logs
- Compare sources and create cited reports
- Detect inconsistencies and missing information
- Keep sensitive source material within the user's environment

### File and data automation

- Classify, rename, convert, and validate files
- Extract structured data from invoices or records
- Process CSV, Excel, Parquet, or PostgreSQL data
- Persist intermediate datasets and confidence-review queues as artifacts

### Long-running migrations and refactoring

- Upgrade frameworks and dependencies
- Migrate databases or storage backends
- Refactor large repositories in batches
- Checkpoint completed modules and continue from the last durable step

## Additional use cases

- DevOps and incident analysis with approval-gated remediation
- Internal business workflows such as contract review and procurement comparison
- Personal knowledge organization and project timelines
- Multi-stage technical writing and documentation production
- Automated testing, regression analysis, and evidence collection
- Local media processing, transcription, subtitles, and indexing
- A local AI gateway for model routing, redaction, caching, and budgets

## MVP demonstrations

1. Implement a feature in a repository and produce code, tests, and a completion report.
2. Analyze a directory of documents and produce a report with source references.
3. Extract invoice data into a structured file and identify low-confidence fields.
4. Run a repository migration in resumable batches with checkpoints.

## Product boundary

Local Central should not be positioned as only a local chat application. It is a durable execution workspace that coordinates agents, tools, state, approvals, and artifacts.
