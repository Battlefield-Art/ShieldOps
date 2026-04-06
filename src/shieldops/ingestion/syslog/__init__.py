"""Syslog ingestion package — RFC 5424 TCP/UDP/HTTP receivers.

Provides async TCP and UDP listeners for RFC 5424 syslog messages, plus an
HTTP endpoint (wired in ``api/routes/webhooks.py``) for firewalled
environments that cannot open raw syslog ports.

Usage::

    from shieldops.ingestion.syslog import start_listeners, stop_listeners

    await start_listeners(tcp_port=6514, udp_port=6514, org_id="acme")
    ...
    await stop_listeners()
"""

from __future__ import annotations

from shieldops.ingestion.syslog.manager import (
    SyslogListenerManager,
    get_manager,
    start_listeners,
    stop_listeners,
)
from shieldops.ingestion.syslog.parser import parse_rfc5424
from shieldops.ingestion.syslog.tcp_listener import SyslogTCPListener
from shieldops.ingestion.syslog.udp_listener import SyslogUDPListener

__all__ = [
    "SyslogListenerManager",
    "SyslogTCPListener",
    "SyslogUDPListener",
    "get_manager",
    "parse_rfc5424",
    "start_listeners",
    "stop_listeners",
]
