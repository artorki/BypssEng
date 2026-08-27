from bypsseng.infrastructure.runtime_session import RuntimeSession

runtime_session = RuntimeSession()


def setup_dynamic_ports():

    return runtime_session.setup_dynamic_ports()


def release_reserved_ports():

    return runtime_session.release_reserved_ports()
