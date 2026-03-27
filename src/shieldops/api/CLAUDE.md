# api/ — FastAPI REST API

RESTful API at `/api/v1/` with JWT auth, OpenAPI auto-gen, 749 endpoints.

## Route Architecture

```
api/
├── app.py              # FastAPI app factory + lifespan
├── auth/
│   ├── dependencies.py # get_current_user dependency
│   ├── models.py       # UserResponse, UserRole
│   └── jwt.py          # JWT token handling
├── routes/             # 70+ route modules
│   ├── agents.py
│   ├── investigations.py
│   ├── {agent_name}.py # Per-agent routes
│   └── ...
├── middleware/          # 14 middleware modules
│   ├── rate_limiter.py
│   ├── tenant_isolation.py
│   ├── billing.py
│   ├── security_headers.py
│   ├── metrics.py
│   └── ...
└── ws/                 # WebSocket support
```

## Adding a New Route

Every agent route follows this pattern:
```python
"""[name] API routes."""
from __future__ import annotations
import time
from typing import Any
import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

router = APIRouter(prefix="/[kebab-name]", tags=["[Title]"])
_runner: Any = None

def set_runner(runner: Any) -> None: ...
def _get_runner() -> Any: ...

class RunRequest(BaseModel):
    tenant_id: str = ""
    model_config = {"extra": "forbid"}

@router.get("/health")    # Health check
@router.post("/run")      # Execute agent (auth required)
@router.get("/runs")      # List past runs
@router.get("/runs/{id}") # Get specific run
```

## Route Registration
Routes are dynamically registered in `app.py` via `__import__`:
```python
for _rname in ("agent_name1", "agent_name2", ...):
    _mod = __import__(f"shieldops.api.routes.{_rname}", ...)
    app.include_router(_mod.router, prefix=settings.api_prefix)
```

## Auth
- JWT tokens via `get_current_user` dependency
- API keys supported
- OIDC/SSO integration
- Roles: ADMIN, ANALYST, VIEWER
