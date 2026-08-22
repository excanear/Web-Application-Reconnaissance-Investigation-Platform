from app.audit import AuditLog


def test_record_appends_an_entry_with_the_given_fields():
    log = AuditLog()
    log.record(module="crtsh", target="example.com", outcome="200", url="https://crt.sh/")

    assert len(log.entries) == 1
    entry = log.entries[0]
    assert entry["module"] == "crtsh"
    assert entry["target"] == "example.com"
    assert entry["outcome"] == "200"
    assert entry["url"] == "https://crt.sh/"
    assert entry["requested_at"] is not None


def test_record_defaults_url_to_none():
    log = AuditLog()
    log.record(module="whois", target="example.com", outcome="success")

    assert log.entries[0]["url"] is None


def test_record_accumulates_multiple_entries_in_order():
    log = AuditLog()
    log.record(module="cloud_range", target="a.example.com", outcome="resolved: 1.2.3.4")
    log.record(module="cloud_range", target="b.example.com", outcome="error: timeout")

    assert [e["target"] for e in log.entries] == ["a.example.com", "b.example.com"]


def test_entries_can_be_cleared():
    log = AuditLog()
    log.record(module="crtsh", target="example.com", outcome="200")
    log.entries.clear()

    assert log.entries == []


from concurrent.futures import ThreadPoolExecutor


def test_record_loses_no_entries_under_concurrent_calls():
    log = AuditLog()

    def do_record(i):
        log.record(module="tech_fingerprint", target=f"host{i}.example.com", outcome="200")

    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(do_record, range(200)))

    assert len(log.entries) == 200
    assert {e["target"] for e in log.entries} == {f"host{i}.example.com" for i in range(200)}
