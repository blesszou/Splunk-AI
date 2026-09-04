import sys
import os
import json

# ── Path injection ─────────────────────────────────────────────────────
app_bin_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.join(app_bin_dir, 'lib')
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)
# ──────────────────────────────────────────────────────────────────────

from spl_guard import guarded
from splunklib.ai.registry import ToolRegistry, ToolContext

registry = ToolRegistry()

# Splunk internal bookkeeping fields to strip from output
_IGNORED_FIELDS = {
    "_bkt", "_cd", "_si", "_serial", "_indextime", "_eventtype_color", 
    "_subsecond", "_kv", "_subseconds", "_kv_field", "linecount"
}

def _clean_event(event: dict) -> dict:
    """Strips noisy Splunk internal metadata and truncates overly long _raw text."""
    clean = {}
    for k, v in event.items():
        if k in _IGNORED_FIELDS or k.startswith("__"):
            continue
        if k == "_raw" and isinstance(v, str) and len(v) > 400:
            clean[k] = v[:400] + "... [truncated]"
        elif isinstance(v, str) and len(v) > 500:
            clean[k] = v[:500] + "... [truncated]"
        else:
            clean[k] = v
    return clean

@registry.tool()
def run_splunk_query(ctx: ToolContext, query: str) -> str:
    """Execute a Splunk SPL query and return results for log analysis."""
    if isinstance(query, list):
        query = " ".join([str(q) for q in query])
    
    clean_query = query.strip()
    if not clean_query.startswith("|") and not clean_query.startswith("search"):
        clean_query = f"search {clean_query}"

    # The query came from the model, so it is untrusted input even though it will
    # run with the search user's full permissions.
    allowed, reason = guarded(clean_query)
    if not allowed:
        return f"Query refused by the read-only guardrail. {reason}"

    try:
        job = ctx.service.jobs.oneshot(clean_query, output_mode="json", count=30)
        res = json.loads(job.read().decode('utf-8'))
        results = res.get("results", [])
        if not results:
            return "No matching events found for this query in Splunk."
        
        # Clean noisy internal metadata and keep results concise
        cleaned_results = [_clean_event(e) for e in results[:15]]
        return json.dumps(cleaned_results, ensure_ascii=False)
    except Exception as e:
        return f"Error executing SPL '{clean_query}': {str(e)}"

if __name__ == "__main__":
    registry.run()