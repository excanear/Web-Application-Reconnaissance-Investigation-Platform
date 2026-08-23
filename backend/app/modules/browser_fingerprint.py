# backend/app/modules/browser_fingerprint.py
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from app import wappalyzer
from app.modules.base import Finding, ReconModule, prioritized_hosts, register_module
from app.ratelimit import CircuitBreaker, RateLimiter
from app.scope import is_in_scope

DEFAULT_RATE_LIMIT = 5.0
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
PAGE_TIMEOUT_MS = 15000

# Each script runs once per host (at most 3 page.evaluate() round trips
# total), regardless of how many thousand js/dom/css technology
# definitions app.wappalyzer.collect_browser_probe_requirements() derived
# the paths/selectors from -- one bulk lookup, not one per technology.
_JS_PATHS_SCRIPT = """(paths) => paths.map((p) => {
    try {
        const v = p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), window);
        if (v === undefined || v === null) return null;
        if (typeof v === 'function') return 'function';
        if (typeof v === 'object') return String(v);
        return v;
    } catch (e) {
        return null;
    }
})"""

_DOM_SCRIPT = """(specs) => specs.map((spec) => {
    try {
        const el = document.querySelector(spec.selector);
        if (!el) return null;
        const attributes = {};
        for (const a of spec.attributes) attributes[a] = el.getAttribute(a);
        const properties = {};
        for (const p of spec.properties) {
            try {
                const v = el[p];
                properties[p] = (v === undefined || v === null) ? null : (typeof v === 'object' ? String(v) : v);
            } catch (e) {}
        }
        return { text: el.textContent || '', attributes: attributes, properties: properties };
    } catch (e) {
        return null;
    }
})"""

_CSS_SCRIPT = """() => {
    let out = '';
    for (const sheet of document.styleSheets) {
        try {
            for (const rule of sheet.cssRules) out += rule.cssText + '\\n';
        } catch (e) {}
    }
    for (const el of document.querySelectorAll('style')) out += (el.textContent || '') + '\\n';
    return out;
}"""


@register_module
class BrowserFingerprintModule(ReconModule):
    """Drives a headless Chromium page load to gather the js/dom/css
    signals app.wappalyzer.match_technologies structurally can't reach
    from a single HTTP GET (see SUPPORTED_CHECK_TYPES vs
    BROWSER_CHECK_TYPES in app/wappalyzer.py) -- roughly a third of the
    vendored technology definitions."""

    name = "browser_fingerprint"
    run_order = 55  # after tech_fingerprint (50), before cve_correlation (90)
    is_active = True

    def run(self, target: str, context: dict) -> list[Finding]:
        hosts = prioritized_hosts(context, target)
        scope = context.get("scope")
        audit = context.get("audit")
        limiter = RateLimiter(context.get("rate_limit", DEFAULT_RATE_LIMIT))
        breaker = CircuitBreaker(
            context.get("circuit_breaker_threshold", DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
        )
        technologies = context.get("wappalyzer_technologies")
        if technologies is None:
            technologies = wappalyzer.load_technologies()
        wappalyzer.load_categories()

        requirements = wappalyzer.collect_browser_probe_requirements(technologies)
        if not requirements.js_paths and not requirements.dom_selectors and not requirements.needs_css:
            return []

        findings: list[Finding] = []
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch()
            except PlaywrightError as exc:
                # Covers both "chromium was never downloaded" and "chromium
                # is downloaded but missing OS shared libraries" (the
                # latter shows up as a launch/target-closed error, not a
                # distinct exception type) -- --with-deps handles both in
                # one command by also apt-installing the missing libs.
                raise RuntimeError(
                    "Playwright's Chromium is not available (not installed, "
                    "or missing OS libraries) - run "
                    "`playwright install --with-deps chromium` to enable "
                    "browser-based fingerprinting"
                ) from exc

            try:
                for index, host in enumerate(hosts):
                    if scope is not None and not is_in_scope(host, None, scope):
                        findings.append(
                            Finding(type="out_of_scope", value=host, data={"module": self.name})
                        )
                        continue

                    limiter.wait()
                    host_findings, reached_host = self._fingerprint_host(
                        browser, host, requirements, technologies, audit
                    )
                    findings.extend(host_findings)

                    if reached_host:
                        breaker.record_success()
                        continue

                    if breaker.record_failure():
                        findings.append(
                            Finding(
                                type="circuit_breaker_tripped",
                                value=host,
                                data={"module": self.name, "skipped_hosts": len(hosts) - index - 1},
                            )
                        )
                        break
            finally:
                browser.close()

        return findings

    def _fingerprint_host(
        self, browser, host: str, requirements, technologies: dict, audit
    ) -> tuple[list[Finding], bool]:
        url = f"https://{host}/"
        page = browser.new_page()
        try:
            try:
                page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded")
            except PlaywrightError as exc:
                if audit is not None:
                    audit.record(module=self.name, target=host, outcome=f"error: {exc}", url=url)
                return [], False

            if audit is not None:
                audit.record(module=self.name, target=host, outcome="loaded", url=url)

            js_values: dict = {}
            if requirements.js_paths:
                raw = page.evaluate(_JS_PATHS_SCRIPT, requirements.js_paths)
                js_values = dict(zip(requirements.js_paths, raw))

            dom_results: dict = {}
            if requirements.dom_selectors:
                specs = [
                    {
                        "selector": selector,
                        "attributes": requirements.dom_selector_specs.get(selector, {}).get(
                            "attributes", []
                        ),
                        "properties": requirements.dom_selector_specs.get(selector, {}).get(
                            "properties", []
                        ),
                    }
                    for selector in requirements.dom_selectors
                ]
                raw = page.evaluate(_DOM_SCRIPT, specs)
                dom_results = dict(zip(requirements.dom_selectors, raw))

            css_text = page.evaluate(_CSS_SCRIPT) if requirements.needs_css else ""
        finally:
            page.close()

        findings = wappalyzer.match_browser_technologies(
            host, js_values=js_values, dom_results=dom_results, css_text=css_text,
            technologies=technologies,
        )
        return findings, True
