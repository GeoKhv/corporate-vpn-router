"""Build the shareable log's fixed vocabulary from product source, never user data."""
import json
from pathlib import Path
import re


def write_terms(root, output):
    terms = set("""
    idle checkingHelper installingHelper preparingRoutes authenticating activatingRoutes connected stopping failed
    checking missing ready desktopAvailable updateRequired repairRequired checkFailed unavailable previousSession
    idle waiting ready error startup session routes ssl ui install launch update
    TimeoutError SSLError SSLCertVerificationError ConnectionResetError ConnectionRefusedError ConnectionError
    BrokenPipeError OSError PermissionError RuntimeError ValueError FileNotFoundError gaierror Refused CancelledError
    EXC_BAD_ACCESS EXC_CRASH EXC_RESOURCE EXC_BAD_INSTRUCTION EXC_BREAKPOINT EXC_GUARD
    SIGKILL SIGTERM SIGSEGV SIGILL SIGABRT SIGTRAP SIGBUS DYLD SIGNAL CODESIGNING
    """.split())
    for folder, extension in [('Backend', '*.py'), ('Sources', '*.swift')]:
        for source in (root / folder).rglob(extension):
            if source.name == 'support_report.py':
                continue
            text = source.read_text()
            # Complete identifier-like literals only. No endpoints, paths, text or binary data.
            terms.update(re.findall(r'''["']([A-Za-z][A-Za-z0-9_-]{0,78})["']''', text))
    output.write_text(json.dumps(sorted(terms), separators=(',', ':')))


if __name__=='__main__':
    import sys
    write_terms(Path(__file__).resolve().parents[1],Path(sys.argv[1]))
