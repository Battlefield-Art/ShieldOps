# db/ — Database Layer

SQLAlchemy async + Alembic migrations + repository pattern.

## Architecture
- `models.py` — SQLAlchemy ORM models
- `session.py` — Async engine + session factory
- `repository.py` — Repository pattern for data access
- `migrations/` — Alembic migration scripts

## Conventions
- Always use async sessions (`async with session_factory() as session`)
- Repository pattern for all data access (never raw SQL in routes)
- PostgreSQL as primary database
- Connection pooling via SQLAlchemy pool_size setting

## Running Migrations
```bash
alembic upgrade head      # Apply all migrations
alembic revision --autogenerate -m "description"  # Create migration
```
