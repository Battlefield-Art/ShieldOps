# src/ — Source Code

All production source code lives in `src/shieldops/`.

See `src/shieldops/CLAUDE.md` for the full package architecture.

## Build & Install
```bash
pip install -e ".[dev]"
```

## Package Entry Point
- `shieldops.api.app:app` — FastAPI application
- `shieldops.cli` — CLI commands
