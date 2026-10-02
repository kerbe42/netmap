"""Host-discovery nmap options: aggressive timing by default, an optional packet-rate floor."""
import subnetsleuth.sweep as sweep
from subnetsleuth.sweep import nmap_ping_opts, set_discovery_rate


def test_discovery_uses_aggressive_timing():
    opts = nmap_ping_opts()
    assert "-T4" in opts  # ~1.25 s max RTT instead of -T3's 10 s
    assert "--min-hostgroup" in opts  # probe the whole /24 at once, not in small chunks
    assert "-sn" in opts


def test_min_rate_is_off_by_default_and_settable():
    set_discovery_rate(0)
    try:
        assert "--min-rate" not in nmap_ping_opts()
        set_discovery_rate(500)
        opts = nmap_ping_opts()
        assert opts[opts.index("--min-rate") + 1] == "500"
        set_discovery_rate(-5)  # clamped to 0 (off)
        assert "--min-rate" not in nmap_ping_opts()
    finally:
        set_discovery_rate(0)  # don't leak the setting into other tests
    assert sweep.NMAP_MIN_RATE == 0
