"""Database persistence layer — SQLAlchemy 2.x async ORM.

The legacy ``Repository`` god class has been demoted to an
internal-only orphan in :mod:`shieldops.db.repository` and is no longer
re-exported. New callers should import :mod:`shieldops.db.fetch`
helpers (``fetch.get``, ``fetch.list_``, ``fetch.save``) or a per-entity
repository from :mod:`shieldops.db.repositories`. See RFC #245.
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
