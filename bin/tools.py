import sys
import os
import json

# ── Path injection ─────────────────────────────────────────────────────
app_bin_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.join(app_bin_dir, 'lib')
if lib_dir not in sys.path:
    sys.path.insert(0, lib_dir)
# ──────────────────────────────────────────────────────────────────────

from splunklib.ai.registry import ToolRegistry, ToolContext

registry = ToolRegistry()

@registry.tool()
def run_splunk_query(ctx: ToolContext, query: str) -> str:
    """Execute a Splunk SPL query and return results for log analysis."""
    if isinstance(query, list):
        query = " ".join([str(q) for q in query])
    if not query.strip().startswith("|") and "head" not in query:
        query = f"search {query} | head 20"
    try:
        job = ctx.service.jobs.oneshot(query, output_mode="json")
        res = json.loads(job.read().decode('utf-8'))
        return json.dumps(res.get("results", [])[:10])
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    registry.run()