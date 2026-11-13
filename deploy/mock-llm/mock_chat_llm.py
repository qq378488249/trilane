#!/usr/bin/env python3
"""Randomly failing OpenAI-compatible Chat Completions mock.

Every request is answered either with a random provider error (401 / 429 / 5xx)
or with a tiny successful completion, so the retry logic in TriLane can be
exercised end to end.

Run:
    python mock_chat_llm.py --port 8787 --error-rate 0.7

The TriLane provider config should point at http://127.0.0.1:8787/v1 with
`adapter = "chat-completions"`; the in-process adapter forwards to
<base_url>/chat/completions and passes the upstream status code through.
"""

import argparse
import json
import random
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_TEXT = "MOCK_OK"

# (status, error type, message, weight)
ERROR_KINDS = [
    (401, "authentication_error", "mock unauthorized", 1),
    (429, "rate_limit_exceeded", "mock rate limit reached", 3),
    (429, "usage_limit_reached", "mock usage limit reached", 1),
    (500, "server_error", "mock internal error", 2),
    (502, "bad_gateway", "mock bad gateway", 1),
    (503, "service_unavailable", "mock service unavailable", 2),
]

OVERLOADED_KIND = (
    503,
    "server_is_overloaded",
    "mock server is overloaded",
)


def pick_error(include_overloaded: bool):
    kinds = list(ERROR_KINDS)
    if include_overloaded:
        kinds.append((*OVERLOADED_KIND, 1))
    total = sum(kind[3] for kind in kinds)
    roll = random.uniform(0, total)
    for status, error_type, message, weight in kinds:
        roll -= weight
        if roll <= 0:
            return status, error_type, message
    return kinds[-1][:3]


def chat_completion_body(model: str, text: str) -> dict:
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def chat_stream_body(model: str, text: str) -> bytes:
    created = int(time.time())
    chunks = [
        {
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": text},
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    ]
    body = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
    body += "data: [DONE]\n\n"
    return body.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockChatLLM/1.0"

    def log_message(self, fmt, *args):  # noqa: A003 - silence default logging
        pass

    def _send(self, status: int, body: bytes, content_type: str, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            request = {}

        index = self.server.request_count = self.server.request_count + 1
        model = request.get("model") or "mock-model"

        if random.random() < self.server.error_rate:
            status, error_type, message = pick_error(self.server.include_overloaded)
            headers = {}
            if status == 429:
                headers["Retry-After"] = str(random.randint(1, 3))
            body = json.dumps(
                {"error": {"message": message, "type": error_type, "code": error_type}}
            ).encode("utf-8")
            print(
                f"[mock] #{index} POST {self.path} -> {status} {error_type}",
                flush=True,
            )
            self._send(status, body, "application/json", headers)
            return

        stream = bool(request.get("stream"))
        print(f"[mock] #{index} POST {self.path} -> 200 ok stream={stream}", flush=True)
        if stream:
            self._send(
                200,
                chat_stream_body(model, self.server.text),
                "text/event-stream",
                {"Cache-Control": "no-cache"},
            )
        else:
            body = json.dumps(chat_completion_body(model, self.server.text)).encode(
                "utf-8"
            )
            self._send(200, body, "application/json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--error-rate",
        type=float,
        default=0.7,
        help="probability of answering with a random error (0..1)",
    )
    parser.add_argument(
        "--text",
        default=DEFAULT_TEXT,
        help="assistant text returned by successful responses",
    )
    parser.add_argument(
        "--include-overloaded",
        action="store_true",
        help="also return 503 server_is_overloaded (not retryable by design)",
    )
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if not 0.0 <= args.error_rate <= 1.0:
        print("--error-rate must be between 0 and 1", file=sys.stderr)
        return 2
    if args.seed is not None:
        random.seed(args.seed)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.error_rate = args.error_rate
    server.include_overloaded = args.include_overloaded
    server.text = args.text
    server.request_count = 0
    print(
        f"[mock] listening on http://{args.host}:{args.port}/v1 "
        f"error_rate={args.error_rate} include_overloaded={args.include_overloaded}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[mock] stopping", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
