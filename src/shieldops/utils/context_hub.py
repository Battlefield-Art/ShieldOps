"""Context Hub — Retrieval-augmented context for ShieldOps agents.

Inspired by andrewyng/context-hub. Instead of relying on LLM training data,
agents fetch real documentation, runbooks, and historical context before acting.

Supports:
- Runbook retrieval (what to do for specific incident types)
- Historical incident context (what worked before for similar issues)
- Infrastructure documentation (service configs, dependencies, SLOs)
- Compliance requirements (what controls apply to this action)
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class ContextType(StrEnum):
    RUNBOOK = "runbook"
    INCIDENT_HISTORY = "incident_history"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    API_DOCS = "api_docs"
    PLAYBOOK = "playbook"


class ContextEntry(BaseModel):
    """A single piece of retrieved context."""

    id: str
    context_type: ContextType
    title: str
    content: str
    relevance_score: float = 0.0
    source: str = ""
    version: str = ""
    last_updated: float = Field(default_factory=time.time)
    annotations: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ContextQuery(BaseModel):
    """A query to the context hub."""

    query: str
    context_types: list[ContextType] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    max_results: int = 5
    min_relevance: float = 0.0


class ContextHub:
    """Central context retrieval system for all ShieldOps agents.

    Agents call hub.search() before making decisions to get:
    - Relevant runbooks for the incident type
    - Historical context from similar past incidents
    - Infrastructure docs for affected services
    - Compliance requirements that apply
    """

    def __init__(self, repository: Any = None) -> None:
        self._repository = repository
        self._cache: dict[str, list[ContextEntry]] = {}
        self._entries: list[ContextEntry] = []
        self._annotations: dict[str, list[str]] = {}
        self._feedback: dict[str, list[dict[str, Any]]] = {}

    def register(self, entry: ContextEntry) -> None:
        """Register a context entry (runbook, doc, playbook)."""
        self._entries.append(entry)
        for tag in entry.tags:
            self._cache.setdefault(tag, []).append(entry)
        logger.info("context_registered", id=entry.id, type=entry.context_type)

    def search(self, query: ContextQuery) -> list[ContextEntry]:
        """Search for relevant context entries.

        Scores entries by term overlap between query and entry title/content.
        Filters by context_type and tags when specified.
        """
        results: list[ContextEntry] = []
        query_terms = set(query.query.lower().split())

        for entry in self._entries:
            # Filter by context type if specified
            if query.context_types and entry.context_type not in query.context_types:
                continue

            # Filter by tags if specified
            if query.tags and not set(query.tags) & set(entry.tags):
                continue

            # Score relevance based on query term matches in title, content, and tags
            title_terms = set(entry.title.lower().split())
            content_words = entry.content.lower().split()
            content_terms = set(content_words[:200])
            tag_terms = {t.lower() for t in entry.tags}
            entry_terms = title_terms | content_terms | tag_terms

            overlap = query_terms & entry_terms
            relevance = len(overlap) / max(len(query_terms), 1)

            if relevance > 0 and relevance >= query.min_relevance:
                entry_copy = entry.model_copy()
                entry_copy.relevance_score = round(relevance, 4)
                results.append(entry_copy)

        # Sort by relevance descending, then by title for stable ordering
        results.sort(key=lambda e: (-e.relevance_score, e.title))
        return results[: query.max_results]

    def get(self, context_id: str) -> ContextEntry | None:
        """Get a specific context entry by ID."""
        for entry in self._entries:
            if entry.id == context_id:
                return entry
        return None

    def annotate(self, context_id: str, note: str) -> bool:
        """Add an annotation to a context entry (agent learning).

        Annotations let agents record what they learned when using
        a particular piece of context, improving future retrieval.
        """
        entry = self.get(context_id)
        if entry is None:
            return False
        self._annotations.setdefault(context_id, []).append(note)
        logger.info("context_annotated", id=context_id, note=note[:100])
        return True

    def feedback(self, context_id: str, helpful: bool, comment: str = "") -> bool:
        """Rate whether a context entry was helpful for the agent's decision.

        Feedback is tracked per entry so we can surface the most useful
        context entries and deprecate unhelpful ones.
        """
        entry = self.get(context_id)
        if entry is None:
            return False
        self._feedback.setdefault(context_id, []).append(
            {
                "helpful": helpful,
                "comment": comment,
                "timestamp": time.time(),
            }
        )
        logger.info("context_feedback", id=context_id, helpful=helpful)
        return True

    def get_annotations(self, context_id: str) -> list[str]:
        """Get all annotations for a context entry."""
        return list(self._annotations.get(context_id, []))

    def get_feedback(self, context_id: str) -> list[dict[str, Any]]:
        """Get all feedback for a context entry."""
        return list(self._feedback.get(context_id, []))

    def list_entries(
        self,
        context_type: ContextType | None = None,
    ) -> list[ContextEntry]:
        """List all entries, optionally filtered by type."""
        if context_type is None:
            return list(self._entries)
        return [e for e in self._entries if e.context_type == context_type]

    def remove(self, context_id: str) -> bool:
        """Remove a context entry by ID."""
        for i, entry in enumerate(self._entries):
            if entry.id == context_id:
                removed = self._entries.pop(i)
                # Clean up cache
                for tag in removed.tags:
                    if tag in self._cache:
                        self._cache[tag] = [e for e in self._cache[tag] if e.id != context_id]
                return True
        return False

    def get_stats(self) -> dict[str, Any]:
        """Get hub statistics."""
        by_type: dict[str, int] = {}
        for entry in self._entries:
            by_type[entry.context_type] = by_type.get(entry.context_type, 0) + 1

        helpful_count = sum(
            1 for feedbacks in self._feedback.values() for fb in feedbacks if fb["helpful"]
        )
        total_feedback = sum(len(v) for v in self._feedback.values())

        return {
            "total_entries": len(self._entries),
            "by_type": by_type,
            "total_annotations": sum(len(v) for v in self._annotations.values()),
            "total_feedback": total_feedback,
            "helpful_ratio": (
                round(helpful_count / total_feedback, 4) if total_feedback > 0 else 0.0
            ),
        }

    def load_default_contexts(self) -> int:
        """Load built-in ShieldOps context entries.

        Returns the number of entries loaded.
        """
        defaults = self._build_default_entries()
        for entry in defaults:
            self.register(entry)
        return len(defaults)

    def _build_default_entries(self) -> list[ContextEntry]:
        """Build default context entries covering common incident types and compliance."""
        return [
            ContextEntry(
                id="runbook-oomkilled",
                context_type=ContextType.RUNBOOK,
                title="OOMKilled Pod Response Runbook",
                content=(
                    "When a pod is OOMKilled:\n"
                    "1. Check current memory usage: kubectl top pod <pod> -n <ns>\n"
                    "2. Review resource limits: kubectl describe pod <pod> -n <ns>\n"
                    "3. Check for memory leaks in application logs\n"
                    "4. If legitimate growth, increase memory limit by 25-50%\n"
                    "5. If leak suspected, capture heap dump before restart\n"
                    "6. Apply updated limits: kubectl apply -f deployment.yaml\n"
                    "7. Monitor for recurrence over 30 minutes\n"
                    "CAUTION: Do not increase limits beyond node capacity. "
                    "Check node allocatable memory first."
                ),
                source="shieldops/runbooks/kubernetes",
                version="1.2",
                tags=["kubernetes", "oom", "memory", "pod", "oomkilled"],
            ),
            ContextEntry(
                id="runbook-high-cpu",
                context_type=ContextType.RUNBOOK,
                title="High CPU Investigation Runbook",
                content=(
                    "When CPU usage exceeds threshold (>85% sustained):\n"
                    "1. Identify top processes: top -bn1 | head -20 (Linux) "
                    "or kubectl top pod --sort-by=cpu\n"
                    "2. Check if autoscaler is active and functioning\n"
                    "3. Review recent deployments that may have caused regression\n"
                    "4. Check for runaway queries or infinite loops in logs\n"
                    "5. If single pod, consider vertical scaling or code profiling\n"
                    "6. If cluster-wide, check for noisy neighbor or DDoS\n"
                    "7. Scale horizontally if HPA maxReplicas not reached\n"
                    "THRESHOLD: Autonomous action if CPU >90% for >5 min on "
                    "non-production. Production requires approval >85%."
                ),
                source="shieldops/runbooks/compute",
                version="1.1",
                tags=["cpu", "high-cpu", "performance", "scaling", "investigation"],
            ),
            ContextEntry(
                id="runbook-ssl-cert-expiry",
                context_type=ContextType.RUNBOOK,
                title="SSL Certificate Expiry Response",
                content=(
                    "When SSL certificate is expiring or expired:\n"
                    "1. Check expiry: openssl x509 -enddate -noout -in cert.pem\n"
                    "2. If managed by cert-manager, check Certificate resource status\n"
                    "3. If Let's Encrypt, verify ACME challenge can complete\n"
                    "4. For manual certs, trigger renewal through vault/PKI\n"
                    "5. Verify new cert chain: openssl verify -CAfile ca.pem cert.pem\n"
                    "6. Reload ingress/load balancer to pick up new cert\n"
                    "7. Verify with: curl -vI https://<domain> 2>&1 | grep expire\n"
                    "CRITICAL: Expired certs cause immediate customer impact. "
                    "Escalate if <24h remaining and auto-renewal failing."
                ),
                source="shieldops/runbooks/tls",
                version="1.0",
                tags=["ssl", "tls", "certificate", "expiry", "security"],
            ),
            ContextEntry(
                id="runbook-disk-full",
                context_type=ContextType.RUNBOOK,
                title="Disk Full Remediation Runbook",
                content=(
                    "When disk usage exceeds 90%:\n"
                    "1. Identify largest files: du -sh /* | sort -rh | head -10\n"
                    "2. Check for log rotation issues: ls -la /var/log/\n"
                    "3. Clear old container images: docker system prune -f\n"
                    "4. Check for orphaned PVCs in Kubernetes\n"
                    "5. Truncate (don't delete) active log files if needed\n"
                    "6. If persistent, expand volume (EBS/PD resize)\n"
                    "7. Set up monitoring alert at 80% to catch earlier\n"
                    "SAFETY: Never delete data directories without backup verification. "
                    "Never rm -rf on mount points."
                ),
                source="shieldops/runbooks/storage",
                version="1.3",
                tags=["disk", "storage", "full", "capacity", "remediation"],
            ),
            ContextEntry(
                id="compliance-hipaa-phi",
                context_type=ContextType.COMPLIANCE,
                title="HIPAA PHI Access Requirements",
                content=(
                    "Protected Health Information (PHI) handling requirements:\n"
                    "- All PHI access must be logged with user ID, timestamp, "
                    "resource accessed\n"
                    "- Minimum necessary standard: only access PHI needed for task\n"
                    "- PHI at rest must be encrypted (AES-256)\n"
                    "- PHI in transit must use TLS 1.2+\n"
                    "- Access requires valid BAA (Business Associate Agreement)\n"
                    "- Breach notification required within 60 days\n"
                    "- Audit logs retained for minimum 6 years\n"
                    "- Agent actions touching PHI require human approval "
                    "regardless of confidence score\n"
                    "SHIELDOPS POLICY: Agents must never log, cache, or store "
                    "PHI in agent state. Use field-level encryption."
                ),
                source="shieldops/compliance/hipaa",
                version="2.0",
                tags=["hipaa", "phi", "healthcare", "compliance", "encryption"],
            ),
            ContextEntry(
                id="compliance-soc2-change",
                context_type=ContextType.COMPLIANCE,
                title="SOC 2 Change Management Controls",
                content=(
                    "SOC 2 Type II change management requirements:\n"
                    "- All changes must have an associated ticket/CR\n"
                    "- Changes require peer review (CC6.1)\n"
                    "- Separation of duties: developer cannot approve own change\n"
                    "- Pre-deployment testing required (CC7.1)\n"
                    "- Rollback plan documented before deployment\n"
                    "- Change window compliance for production systems\n"
                    "- Emergency changes allowed with post-hoc review within 48h\n"
                    "- Audit trail retention: minimum 1 year\n"
                    "SHIELDOPS POLICY: Agent remediations count as changes. "
                    "Auto-generated CR created for each action. Rollback tested."
                ),
                source="shieldops/compliance/soc2",
                version="1.5",
                tags=["soc2", "change-management", "compliance", "audit", "controls"],
            ),
            ContextEntry(
                id="compliance-pci-dss",
                context_type=ContextType.COMPLIANCE,
                title="PCI-DSS Cardholder Data Requirements",
                content=(
                    "PCI-DSS v4.0 cardholder data environment (CDE) controls:\n"
                    "- Cardholder data must never be stored in plaintext\n"
                    "- PAN must be masked when displayed (show only last 4)\n"
                    "- Strong cryptography for storage (AES-256, RSA-2048+)\n"
                    "- Network segmentation isolating CDE from other networks\n"
                    "- Quarterly vulnerability scans (ASV)\n"
                    "- Annual penetration testing\n"
                    "- Access restricted to need-to-know basis (Req 7)\n"
                    "- All access to cardholder data logged and monitored (Req 10)\n"
                    "SHIELDOPS POLICY: Agents operating in CDE scope require "
                    "MFA-verified human approval. No autonomous actions in CDE."
                ),
                source="shieldops/compliance/pci-dss",
                version="4.0",
                tags=["pci-dss", "pci", "cardholder", "compliance", "payment"],
            ),
            ContextEntry(
                id="runbook-k8s-rollback",
                context_type=ContextType.RUNBOOK,
                title="Kubernetes Deployment Rollback Procedure",
                content=(
                    "When a deployment causes errors and needs rollback:\n"
                    "1. Confirm issue: kubectl rollout status deployment/<name>\n"
                    "2. Check rollout history: kubectl rollout history deployment/<name>\n"
                    "3. Rollback to previous: kubectl rollout undo deployment/<name>\n"
                    "4. Or specific revision: kubectl rollout undo deployment/<name> "
                    "--to-revision=<n>\n"
                    "5. Verify rollback: kubectl get pods -l app=<name> -w\n"
                    "6. Check service health endpoints\n"
                    "7. Notify team via ChatOps channel\n"
                    "SAFETY: Always check if rollback target revision was stable. "
                    "Rolling back to another broken version makes things worse."
                ),
                source="shieldops/runbooks/kubernetes",
                version="1.4",
                tags=["kubernetes", "rollback", "deployment", "k8s", "remediation"],
            ),
            ContextEntry(
                id="runbook-db-connection-pool",
                context_type=ContextType.RUNBOOK,
                title="Database Connection Pool Exhaustion",
                content=(
                    "When database connection pool is exhausted:\n"
                    "1. Check active connections: SELECT count(*) FROM "
                    "pg_stat_activity WHERE state='active';\n"
                    "2. Identify long-running queries: SELECT pid, now()-query_start "
                    "AS duration, query FROM pg_stat_activity WHERE state='active' "
                    "ORDER BY duration DESC;\n"
                    "3. Check for connection leaks in application (connections "
                    "not returned to pool)\n"
                    "4. Terminate idle connections if needed: SELECT "
                    "pg_terminate_backend(pid) FROM pg_stat_activity WHERE "
                    "state='idle' AND query_start < now() - interval '10 min';\n"
                    "5. Increase pool size temporarily (max_connections in pgbouncer)\n"
                    "6. Review application connection handling code\n"
                    "CAUTION: Terminating active queries can cause data corruption "
                    "if mid-transaction. Prefer canceling over terminating."
                ),
                source="shieldops/runbooks/database",
                version="1.1",
                tags=[
                    "database",
                    "postgres",
                    "connection-pool",
                    "pool",
                    "exhaustion",
                    "db",
                ],
            ),
            ContextEntry(
                id="runbook-memory-leak",
                context_type=ContextType.RUNBOOK,
                title="Memory Leak Investigation Procedure",
                content=(
                    "When memory leak is suspected (steady growth without release):\n"
                    "1. Confirm trend: check memory usage over 24h (not just spikes)\n"
                    "2. Capture heap dump (Java: jmap, Python: tracemalloc, "
                    "Go: pprof)\n"
                    "3. Compare heap dumps at different times to find growing objects\n"
                    "4. Check for common leak patterns:\n"
                    "   - Unbounded caches or maps\n"
                    "   - Event listeners not unregistered\n"
                    "   - Circular references preventing GC\n"
                    "   - File descriptors or DB connections not closed\n"
                    "5. If in Kubernetes, check container memory vs pod limit\n"
                    "6. Short-term: schedule periodic restarts (CronJob)\n"
                    "7. Long-term: fix root cause in application code\n"
                    "IMPORTANT: Heap dumps may contain sensitive data. Handle "
                    "per data classification policy."
                ),
                source="shieldops/runbooks/application",
                version="1.0",
                tags=["memory", "leak", "memory-leak", "investigation", "heap"],
            ),
            ContextEntry(
                id="incident-history-oom-api",
                context_type=ContextType.INCIDENT_HISTORY,
                title="Past Incident: API Gateway OOMKilled (INC-2024-0847)",
                content=(
                    "Incident: API gateway pods OOMKilled during traffic spike.\n"
                    "Root cause: Unbounded request body buffering in middleware.\n"
                    "Resolution: Set request body size limit to 10MB, increased "
                    "memory limit from 512Mi to 1Gi.\n"
                    "Time to resolve: 23 minutes (automated detection + human "
                    "approval for limit change).\n"
                    "Lesson learned: Always set request body limits on ingress "
                    "middleware. Memory limits should be 2x typical usage."
                ),
                source="shieldops/incidents/INC-2024-0847",
                version="1.0",
                tags=["oom", "oomkilled", "api", "gateway", "memory", "incident"],
            ),
            ContextEntry(
                id="incident-history-disk-logs",
                context_type=ContextType.INCIDENT_HISTORY,
                title="Past Incident: Disk Full from Unrotated Logs (INC-2024-1203)",
                content=(
                    "Incident: Production nodes hit 100% disk usage.\n"
                    "Root cause: Log rotation config was overwritten during "
                    "OS upgrade. Application logs grew to 180GB.\n"
                    "Resolution: Restored logrotate config, truncated active "
                    "log files (not deleted), added disk usage alert at 80%.\n"
                    "Time to resolve: 45 minutes.\n"
                    "Lesson learned: Include logrotate config in IaC. Monitor "
                    "disk at 80%, not 95%. Truncate, never delete active logs."
                ),
                source="shieldops/incidents/INC-2024-1203",
                version="1.0",
                tags=["disk", "full", "logs", "storage", "incident", "logrotate"],
            ),
            ContextEntry(
                id="infra-k8s-hpa-config",
                context_type=ContextType.INFRASTRUCTURE,
                title="Kubernetes HPA Configuration Standards",
                content=(
                    "HPA configuration standards for ShieldOps services:\n"
                    "- minReplicas: 2 (production), 1 (staging/dev)\n"
                    "- maxReplicas: 10 (default), adjust per service load profile\n"
                    "- CPU target: 70% utilization\n"
                    "- Memory target: 80% utilization\n"
                    "- Scale-up stabilization: 60 seconds\n"
                    "- Scale-down stabilization: 300 seconds\n"
                    "- Custom metrics supported via Prometheus adapter\n"
                    "- Always set resource requests AND limits on pods for HPA "
                    "to function correctly."
                ),
                source="shieldops/infrastructure/kubernetes",
                version="1.2",
                tags=["kubernetes", "hpa", "autoscaling", "infrastructure", "k8s"],
            ),
            ContextEntry(
                id="playbook-incident-response",
                context_type=ContextType.PLAYBOOK,
                title="Standard Incident Response Playbook",
                content=(
                    "ShieldOps standard incident response procedure:\n"
                    "1. DETECT: Alert received and validated (auto or manual)\n"
                    "2. TRIAGE: Classify severity (P1-P4), assign responder\n"
                    "3. INVESTIGATE: Gather logs, metrics, traces for root cause\n"
                    "4. CONTAIN: Stop the bleeding (scale, rollback, block)\n"
                    "5. REMEDIATE: Apply fix (code change, config update, infra)\n"
                    "6. VERIFY: Confirm fix resolves issue, monitor for recurrence\n"
                    "7. COMMUNICATE: Update stakeholders, status page\n"
                    "8. POSTMORTEM: Blameless review within 48 hours\n"
                    "For P1/P2: agents auto-execute steps 1-4, human approval "
                    "for step 5. For P3/P4: fully autonomous."
                ),
                source="shieldops/playbooks/incident-response",
                version="2.1",
                tags=[
                    "incident",
                    "response",
                    "playbook",
                    "procedure",
                    "remediation",
                    "investigation",
                ],
            ),
        ]
