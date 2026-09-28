"""
NetScanTools PRO - Modules Package
AeRoLogic Modular Suite

Widget imports are lazy (PEP 562): importing the `modules` package itself
never requires Qt, so the Qt-free service modules (target_validation,
packet_codecs, dns_service, whois_service, ssl_service, ping_stats,
target_io, observation, observation_query) can be imported and unit-tested without PyQt6 installed.
"""

_WIDGETS = {
    "SystemActivityWidget": ".system_activity",
    "PacketAnalysisWidget": ".packet_analysis",
    "DNSToolsWidget": ".dns_tools",
    "SSLScannerWidget": ".ssl_scanner",
    "WhoisWidget": ".whois_utils",
}

__all__ = sorted(_WIDGETS)


def __getattr__(name):
    if name in _WIDGETS:
        import importlib
        module = importlib.import_module(_WIDGETS[name], __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
