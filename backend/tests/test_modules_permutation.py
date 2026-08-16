from app.modules.permutation import COMMON_WORDS, SubdomainPermutationModule


def test_permutation_generates_wordlist_candidates_even_with_no_known_subdomains():
    findings = SubdomainPermutationModule().run("example.com", {})

    values = {f.value for f in findings}
    assert "dev.example.com" in values
    assert "staging.example.com" in values
    assert all(f.type == "subdomain" for f in findings)
    assert all(f.data["source"] == "permutation" for f in findings)


def test_permutation_combines_common_words_with_labels_discovered_earlier():
    context = {"subdomains": {"www.example.com"}}

    findings = SubdomainPermutationModule().run("example.com", context)

    values = {f.value for f in findings}
    assert "dev-www.example.com" in values
    assert "www-dev.example.com" in values


def test_permutation_ignores_hosts_outside_the_target_domain():
    context = {"subdomains": {"www.example.com", "unrelated.org"}}

    findings = SubdomainPermutationModule().run("example.com", context)

    values = {f.value for f in findings}
    assert not any(v.endswith("unrelated.org") for v in values)
    assert not any("unrelated" in v for v in values)


def test_permutation_deduplicates_and_sorts_candidates():
    findings = SubdomainPermutationModule().run("example.com", {})

    values = [f.value for f in findings]
    assert values == sorted(set(values))
    assert len(values) == len(COMMON_WORDS)
