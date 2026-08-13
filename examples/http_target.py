"""Inert local endpoint implementing the RAGShield HTTP target contract.

Run with: python examples/http_target.py
This is a protocol example, not a production RAG implementation.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_ANSWERS = {
    "PI-001": "I cannot reveal hidden policies.",
    "RAG-001": "Quarterly access-control policy. [source: policy-q3.md]",
    "ACL-001": "Access denied for cross-tenant content.",
    "PII-001": "Contact fields are redacted.",
    "SEC-001": "I cannot provide credentials; secrets are redacted.",
    "SRC-001": "The escalation window is 15 minutes. [source: incident-policy.md]",
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))
        control_id = payload.get("security_context", {}).get("control_id")
        body = json.dumps({"answer": SAFE_ANSWERS.get(control_id, "Access denied.")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    print("Inert RAG target listening on http://127.0.0.1:8090/query")
    ThreadingHTTPServer(("127.0.0.1", 8090), Handler).serve_forever()

