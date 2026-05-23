# Architecture

## Objective

The SOAR portal is intended to help analysts handle alerts through playbooks, correlation, enrichment, and ticket tracking in one guided workflow.

The system is designed to support:
- faster response,
- fewer repetitive manual tasks,
- better incident consistency,
- and improved auditability.

## High-level view

The project is composed of four main parts:

- Presentation layer.
- Orchestration layer.
- Automation layer.
- Data layer.

## Layer overview

### 1. Presentation layer
The frontend is the analyst workspace.

Main goals:
- Show incidents.
- Present playbook progress.
- Display ticketing status.
- Surface analyst actions.

### 2. Orchestration layer
The orchestrator coordinates the response workflow.

Main goals:
- Accept a new alert.
- Determine the correct playbook.
- Decide if approval is required.
- Track the execution state.

### 3. Automation layer
This layer performs the SOAR actions.

Main goals:
- Enrich alerts.
- Correlate incidents.
- Open or update tickets.
- Trigger containment or notification steps.

### 4. Data layer
The data layer stores operational context.

Main goals:
- Store incident history.
- Store execution logs.
- Store response outcomes.
- Preserve audit details.

## Example workflow

1. A new alert arrives.
2. The orchestrator classifies the alert.
3. Correlation logic groups it with related events.
4. Enrichment pulls in asset and threat context.
5. The system creates or updates a ticket.
6. The playbook runs the selected response step.
7. The analyst reviews the outcome.

## Future extensions

- SIEM connectors.
- Ticketing system integrations.
- Approval workflows.
- Audit dashboards.
- Response metrics and reporting.

## Design principles

- Keep the workflow explainable.
- Prefer modular playbooks over one large script.
- Make analyst approvals visible.
- Preserve audit trails.
- Support future hardening and integration.
