"""Firebreak: agentic CSOC -> IR engine. See README.md and docs/.

Dependencies normally come from a virtual environment (pip install -r requirements.txt). A
private `.rag_libs/` folder at the repo root (pip install --target .rag_libs ...) is also
supported, so the original rag.py setup keeps working; it must be added as an absolute path.
"""
import os
import sys

_LIBS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".rag_libs")
if os.path.isdir(_LIBS) and _LIBS not in sys.path:
    sys.path.insert(0, _LIBS)
