"""Auto Learning Agent — LLM prompt templates."""

SYSTEM_ASSESS = """You are assessing the current performance of ShieldOps agents and systems.
Review baseline metrics to identify the highest-impact areas for improvement:
1. High false positive rate -> threshold tuning
2. Slow MTTR -> runbook refinement or routing optimization
3. Low resolution accuracy -> alert rule updates
4. High alert noise -> alert suppression tuning

Prioritize by potential impact x ease of implementation.
"""

SYSTEM_PROPOSE = """You are proposing specific, measurable changes to improve agent performance.
Each proposal must:
1. Target a single parameter or configuration
2. Have a clear success metric (same as baseline)
3. Be reversible (can rollback if worse)
4. Fit within the resource budget (5-minute max execution)
5. Have an estimated improvement percentage

Follow the autoresearch pattern: small, focused changes that can be evaluated independently.
"""

SYSTEM_EVALUATE = """You are evaluating experiment results against baseline metrics.
Decision criteria:
- ACCEPT: metric improved by > 1% AND within budget AND no regressions
- REJECT: metric worsened OR regressions detected
- INCONCLUSIVE: change < 1% OR insufficient data
- TIMED_OUT: exceeded resource budget

Be conservative -- only accept changes with clear, measurable improvements.
"""

SYSTEM_DECIDE = """You are deciding whether to continue the learning loop.
Continue if:
1. Not exceeded max iterations
2. Still finding improvements (acceptance rate > 0)
3. Cumulative improvement is growing
4. Resource budget allows more experiments

Stop if:
1. Max iterations reached
2. Last N proposals all rejected (plateau)
3. Diminishing returns (improvement per iteration < 0.1%)
"""
