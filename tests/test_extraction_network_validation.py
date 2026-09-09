from auto_unpack.extraction import validation
from auto_unpack.extraction.indicators import make_indicator


def test_dns_validation_is_separate_from_business_rank(monkeypatch):
    item = make_indicator("https://api.sample.net/v1", "dex", "classes.dex")
    monkeypatch.setattr(
        validation,
        "_resolve",
        lambda host, port: ("resolved", ["203.0.113.10"], None),
    )
    validation.validate_indicator_network(item)
    assert item["rank"] == "biz"
    assert item["validation"]["syntax"] == "valid"
    assert item["validation"]["dns"] == "resolved"
    assert item["validation"]["http"] == "not_checked"


def test_http_probe_blocks_non_public_addresses_by_default(monkeypatch):
    item = make_indicator("http://api.sample.net/v1", "dex", "classes.dex")
    monkeypatch.setattr(
        validation,
        "_resolve",
        lambda host, port: ("resolved", ["10.0.0.8"], None),
    )
    validation.validate_indicator_network(item, check_http=True)
    assert item["validation"]["http"] == "blocked_non_public"


def test_http_response_status_is_recorded(monkeypatch):
    item = make_indicator("https://api.sample.net/v1", "dex", "classes.dex")
    monkeypatch.setattr(
        validation,
        "_resolve",
        lambda host, port: ("resolved", ["93.184.216.34"], None),
    )
    monkeypatch.setattr(
        validation,
        "_probe_http",
        lambda url, addresses, timeout: ("responded", 401, None),
    )
    validation.validate_indicator_network(item, check_http=True)
    assert item["validation"]["http"] == "responded"
    assert item["validation"]["http_status"] == 401
