"""python -m capstone.web [--port 8765]  ->  http://127.0.0.1:8765"""
import argparse

from .. import retrieval  # noqa: F401  (puts .rag_libs on sys.path before uvicorn is imported)


def main():
    ap = argparse.ArgumentParser(prog="python -m capstone.web")
    ap.add_argument("--org", default=None, help="org pack id or path (default: $SOC_ORG or demo-corp)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    from .. import org as orgmod
    org = orgmod.activate(args.org)
    import uvicorn
    from . import server
    print("SOC -> IR console for org '{}': http://{}:{}   (API docs at /docs)".format(org.id, args.host, args.port))
    print("Webhook: POST http://{}:{}/api/ingest/<source>   sources: {}".format(
        args.host, args.port, ", ".join(sorted(org.sources()))))
    if server.INGEST_KEY_SOURCE.startswith("env"):
        print("Ingest API key: from {}".format(server.INGEST_KEY_SOURCE))
    else:   # no key configured: show the one-time key so the operator can use it
        print("Ingest API key (generated, valid until restart; set ${} to fix it): {}".format(
            server._KEY_ENV, server.INGEST_KEY))
    uvicorn.run(server.app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
