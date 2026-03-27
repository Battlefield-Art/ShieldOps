# utils/ — Shared Utilities

Cross-cutting utilities used by all modules.

## Key Files

| File | Purpose |
|------|---------|
| `llm.py` | Singleton ChatAnthropic client, `llm_structured()` function |
| `llm_router.py` | Cost-optimized routing: Haiku/Sonnet/Opus by complexity |
| `llm_providers.py` | Multi-cloud LLM: Anthropic, Bedrock, Vertex, Azure OpenAI |
| `strands_agent.py` | AWS Bedrock Strands Agent integration |
| `context_hub.py` | Retrieval-augmented context for agents |

## LLM Usage Pattern
```python
from shieldops.utils.llm import llm_structured

result = await llm_structured(
    system_prompt="You are a security analyst...",
    user_prompt=f"Analyze: {context}",
    schema=MyOutputModel,  # Pydantic model for structured output
)
```

Always wrap in try/except:
```python
try:
    result = await llm_structured(...)
except Exception:
    logger.debug("llm_fallback", agent="my_agent", node="my_node")
    # Use heuristic fallback
```

## LLM Router
- Simple tasks → Haiku ($0.001/1K tokens)
- Moderate tasks → Sonnet ($0.003/1K tokens)
- Complex tasks → Opus ($0.015/1K tokens)
