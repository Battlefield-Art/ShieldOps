"""Database persistence layer — SQLAlchemy 2.x async ORM.

The legacy 2,005-LOC ``Repository`` god class was deleted in RFC #245
PR-3. Callers should use :mod:`shieldops.db.fetch` helpers
(``fetch.get``, ``fetch.list_``, ``fetch.save``) for the 99% path or a
per-entity repository from :mod:`shieldops.db.repositories` for
cross-entity queries.
"""

from shieldops.db.models import AgentSession, AuditLog, InvestigationRecord, RemediationRecord
from shieldops.db.models_connector import ConnectorConfig
from shieldops.db.session import create_async_engine, get_session

__all__ = [
    "AgentSession",
    "AuditLog",
    "ConnectorConfig",
    "InvestigationRecord",
    "RemediationRecord",
    "create_async_engine",
    "get_session",
]
