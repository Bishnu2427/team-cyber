"""
Fix Agent — enriches raw findings with AI-generated root cause,
impact analysis, and remediation recommendations.
Uses tool-grounded reasoning: LLM interprets tool output, does NOT guess.
"""
import json
from typing import List
from models.model_router import router

_PROMPT = """You are a senior application security engineer performing a code security review.
A security scanning tool produced the finding below. Analyse it and respond ONLY with JSON.

Finding:
{finding}

Required JSON:
{{
  "root_cause": "why this vulnerability exists (specific technical reason)",
  "impact": "what an attacker can achieve if exploited",
  "fix": "exact remediation steps or code pattern",
  "owasp": "OWASP Top 10 2021 category (e.g. A03:2021-Injection)",
  "confidence": 0.0
}}"""


def run_fix_recommendations(findings: List[dict], tech_stack: List[str]) -> List[dict]:
    if not findings:
        return []
    llm = router.reasoning()
    enriched = []
    for f in findings:
        if f.get("root_cause") and f.get("fix"):
            enriched.append(f)
            continue
        try:
            resp    = llm.invoke(_PROMPT.format(finding=json.dumps(f, indent=2, default=str)))
            content = getattr(resp, "content", str(resp))
            s, e    = content.find("{"), content.rfind("}") + 1
            if s >= 0 and e > s:
                patch = json.loads(content[s:e])
                f.update({k: v for k, v in patch.items() if v})
        except Exception as exc:
            print(f"[fix_agent] {exc}")
        enriched.append(f)
    return enriched
