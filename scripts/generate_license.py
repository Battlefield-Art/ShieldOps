#!/usr/bin/env python3
"""Generate a signed ShieldOps license JWT.

Usage:
    python scripts/generate_license.py \\
        --org-id acme \\
        --tier professional \\
        --expires 2027-01-01

The signing key is read from the ``LICENSE_SIGNING_KEY`` environment variable.
For production this should be an RSA private key (PEM). For tests, set
``LICENSE_SIGNING_ALGORITHM=HS256`` and use a shared secret.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

from shieldops.licensing.models import LicenseTier
from shieldops.licensing.signer import sign_license


def _parse_expires(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"invalid --expires date: {value} ({exc})") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a signed ShieldOps license JWT")
    parser.add_argument("--org-id", required=True, help="Organization identifier")
    parser.add_argument(
        "--tier",
        required=True,
        choices=[t.value for t in LicenseTier],
        help="License tier",
    )
    parser.add_argument(
        "--expires",
        required=True,
        help="Expiration date (ISO-8601, e.g. 2027-01-01)",
    )
    parser.add_argument(
        "--agent-limit",
        type=int,
        default=None,
        help="Override agent limit (defaults to tier limit)",
    )
    parser.add_argument(
        "--metadata",
        default=None,
        help="JSON metadata to embed in the license",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the JWT to this file instead of stdout",
    )
    args = parser.parse_args(argv)

    key = os.getenv("LICENSE_SIGNING_KEY")
    if not key:
        print("ERROR: LICENSE_SIGNING_KEY env var is not set", file=sys.stderr)
        return 2

    algorithm = os.getenv("LICENSE_SIGNING_ALGORITHM", "RS256")
    expires_at = _parse_expires(args.expires)
    metadata = json.loads(args.metadata) if args.metadata else None

    if algorithm.startswith("HS"):
        token = sign_license(
            org_id=args.org_id,
            tier=args.tier,
            expires_at=expires_at,
            agent_limit=args.agent_limit,
            metadata=metadata,
            hmac_secret=key,
            algorithm=algorithm,
        )
    else:
        token = sign_license(
            org_id=args.org_id,
            tier=args.tier,
            expires_at=expires_at,
            agent_limit=args.agent_limit,
            metadata=metadata,
            private_key=key,
            algorithm=algorithm,
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
        print(f"wrote license to {args.output}", file=sys.stderr)
    else:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
