# tests/ — Test Suite

1,961 test files with comprehensive coverage.

## Test Structure
```
tests/
├── conftest.py          # Root fixtures (auth mock, middleware reset)
├── unit/                # Unit tests (mirror source structure)
│   ├── agents/          # Agent-specific tests (151 files)
│   ├── api/             # API route tests
│   ├── middleware/       # Middleware tests
│   └── test_*.py        # Engine/module tests
├── integration/         # Integration tests (93+ files)
│   ├── test_*_graph.py  # Agent graph compilation + pipeline tests
│   ├── test_e2e_*.py    # End-to-end workflow tests
│   └── test_bdd_*.py    # BDD security scenario tests
├── load/                # Load tests (k6)
├── performance/         # Performance benchmarks
├── resilience/          # Resilience tests
└── system/              # System-level tests
```

## Test Patterns

### Unit Test (Agent)
```python
class TestEnums:
    def test_stage_values(self): ...

class TestModels:
    def test_state_defaults(self):
        s = AgentState()
        assert s.error == ""  # ALWAYS str, never None

class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return AgentToolkit()

    @pytest.mark.asyncio
    async def test_method(self, toolkit): ...

class TestGraph:
    def test_graph_compiles(self): ...
```

### BDD Test (Given/When/Then)
```python
class TestPromptInjectionDefense:
    """Feature: Prompt injection is detected and blocked."""

    async def test_direct_injection_blocked(self):
        """Given a prompt with injection,
        When analyzed by prompt shield,
        Then it should be blocked."""
```

### Integration Test
```python
def test_graph_compiles():
    sg = create_{name}_graph()
    assert sg.compile() is not None

def test_state_defaults():
    s = State()
    assert s.error == ""
```

## Running Tests
```bash
pytest tests/unit/ -v                    # Unit tests
pytest tests/integration/ -v             # Integration tests
pytest tests/unit/agents/ -q             # Agent-specific tests
pytest tests/ -v --cov=src/shieldops     # With coverage
```

## Key Convention
- `error` field MUST default to `""` (empty string), never `None`
- Use `pytest.mark.asyncio` for async tests
- Use `pytest.skip("Requires dependencies")` for external dependency tests
