


"""
DEPRECATED (HANDOFF Sec 18):
This file is now a thin wrapper. All port allocation logic has been moved to
bypsseng.infrastructure.runtime_session.RuntimeSession to encapsulate state
and prevent global mutable variable issues.

This file is kept temporarily to prevent ImportError during the transition phase.
"""

from bypsseng.infrastructure.runtime_session import RuntimeSession


runtime_session = RuntimeSession()

def setup_dynamic_ports():
    """Wrapper for RuntimeSession.setup_dynamic_ports()"""
    return runtime_session.setup_dynamic_ports()

def release_reserved_ports():
    """Wrapper for RuntimeSession.release_reserved_ports()"""
    return runtime_session.release_reserved_ports()