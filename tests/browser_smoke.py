"""CI-only browser check; run with `uv run --with playwright==1.64.1 python tests/browser_smoke.py`."""
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from test_contract import BrowserContract


def main():
    results = Path("test-results")
    results.mkdir(exist_ok=True)
    # Reuse the real HTTP contract fixture, not a mock API or private export.
    BrowserContract.setUpClass()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(
                viewport={"width": 1440, "height": 1000}, device_scale_factor=2
            )
            context.tracing.start(screenshots=True, snapshots=True, sources=True)
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            try:
                pending = []
                page.route("**/api/meta", lambda route: pending.append(route))
                page.route("**/api/events", lambda route: pending.append(route))
                page.goto(BrowserContract.url, wait_until="domcontentloaded")
                loading = page.get_by_role("status").filter(has_text="Opening local evidence")
                expect(loading).to_be_visible()
                page.screenshot(path=str(results / "initial-loading.png"))
                pending.pop().continue_()
                loading = page.locator("#app-loading")
                expect(loading).to_have_text("Loading events · UTC…")
                expect(loading).to_be_visible()
                page.screenshot(path=str(results / "initial-events-loading.png"))
                pending.pop().continue_()
                rows = page.locator("#events .tabulator-row")
                expect(page.locator("#load-status")).to_have_text("5 loaded · all", timeout=30000)
                expect(loading).to_be_hidden()
                expect(rows).to_have_count(5)
                expect(page.locator("#coverage")).to_contain_text("5 events")
                page.screenshot(path=str(results / "events.png"))

                zone = page.get_by_role("combobox", name="Timezone", exact=True)
                zone.fill("Asia/Jakarta")
                zone.press("Tab")
                expect(loading).to_have_text("Applying Asia/Jakarta…")
                expect(loading).to_be_visible()
                page.screenshot(path=str(results / "timezone-loading.png"))
                pending.pop().continue_()
                expect(loading).to_have_text("Loading events · Asia/Jakarta…")
                expect(loading).to_be_visible()
                page.screenshot(path=str(results / "timezone-events-loading.png"))
                pending.pop().continue_()
                expect(rows.first.locator('[tabulator-field="time_local"]')).to_contain_text("2026-10-26 00:00:00")
                expect(loading).to_be_hidden()

                # Failed metadata must restore the timezone and dismiss the spinner.
                zone.fill("Asia/Singapore")
                zone.press("Tab")
                expect(loading).to_have_text("Applying Asia/Singapore…")
                pending.pop().fulfill(status=500, content_type="application/json", body='{"error":"Synthetic metadata failure"}')
                expect(loading).to_be_hidden()
                expect(zone).to_have_value("Asia/Jakarta")
                expect(page.locator("#error")).to_contain_text("Synthetic metadata failure")
                page.unroute("**/api/meta")
                page.unroute("**/api/events")
                zone.fill("UTC")
                zone.press("Tab")
                expect(rows.first.locator('[tabulator-field="time_local"]')).to_contain_text("2026-10-25 17:00:00")
                expect(loading).to_be_hidden()

                page.locator("#search").fill("SendCommand")
                page.locator("#search").press("Enter")
                expect(page.locator("#load-status")).to_have_text("3 loaded · all")
                expect(rows).to_have_count(3)
                for row in rows.all():
                    expect(row.locator('[tabulator-field="event_name"] .cell-text')).to_have_text("SendCommand")
                page.screenshot(path=str(results / "search.png"))

                zone = page.get_by_role("combobox", name="Timezone", exact=True)
                expect(zone).to_have_attribute("list", "timezone-choices")
                expect(page.locator('#timezone-choices option[value="Asia/Singapore"]')).to_have_count(1)
                zone.fill("Asia/Singapore")
                with page.expect_response(lambda response: "/api/events" in response.url) as refreshed:
                    zone.press("Tab")
                selection = refreshed.value.request.post_data_json
                assert selection["timezone"] == "Asia/Singapore"
                assert selection["search"] == "SendCommand"
                assert selection["start"] == "2026-10-24T16:59:59.000Z"
                expect(rows).to_have_count(3)
                expect(rows.first.locator('[tabulator-field="time_local"]')).to_contain_text("2026-10-26 00:59:59")
                expect(page.locator("#start")).to_have_value("2026-10-25 00:59:59")
                assert page.evaluate("localStorage.getItem('timezone')") == "Asia/Singapore"
                page.screenshot(path=str(results / "timezone-singapore.png"))

                zone.fill("Not/AZone")
                zone.press("Tab")
                expect(zone).to_have_value("Asia/Singapore")
                expect(page.locator("#search")).to_have_value("SendCommand")
                page.locator("#back").click()
                expect(zone).to_have_value("UTC")
                expect(rows.first.locator('[tabulator-field="time_local"]')).to_contain_text("2026-10-25 16:59:59")
                page.locator("#forward").click()
                expect(zone).to_have_value("Asia/Singapore")
                page.reload()
                expect(zone).to_have_value("Asia/Singapore", timeout=30000)
                expect(page.locator("#load-status")).to_have_text("5 loaded · all")
                expect(page.locator("#start")).to_have_value("2026-10-25 00:59:59")

                # Context is read-only; focus/click must not open the event row or alter its query.
                identity = rows.first.locator('[tabulator-field="identity"] .cell-text')
                identity.focus()
                card = page.locator("#reference-card")
                expect(card).to_be_visible()
                expect(card).to_contain_text("Observed events")
                expect(card).to_contain_text("arn:aws:iam::123:user/alice")
                page.screenshot(path=str(results / "identity-reference.png"))
                page.keyboard.press("Escape")
                expect(card).to_be_hidden()
                target = rows.first.locator('[tabulator-field="target"] .cell-text')
                target.click()
                expect(card).to_be_visible()
                expect(card).to_contain_text("application")
                expect(card).to_contain_text("2026-10-29T15:01:00Z")
                expect(card).to_contain_text("not proof of incident-time")
                page.screenshot(path=str(results / "machine-reference.png"))
                page.keyboard.press("Escape")
                ip = rows.first.locator('[tabulator-field="source_ip"] .cell-text')
                page.evaluate("() => { table.scrollToColumn('source_ip', 'center', false); }")
                ip.hover(position={"x": 8, "y": 8})
                expect(card).to_be_visible()
                expect(card).to_contain_text("IP enrichment is an address lookup")
                page.screenshot(path=str(results / "ip-reference.png"))
                page.keyboard.press("Escape")
                expect(rows).to_have_count(5)

                page.locator("#inventory-tab").click()
                expect(page.locator("#inventory-panel")).to_be_visible()
                expect(page.locator(".time-panel")).to_be_hidden()
                expect(page.locator("#rail")).to_be_visible()
                nodes = page.locator("#inventory-topology .inventory-node")
                expect(nodes).to_have_count(4)
                assert page.locator("#inventory-canvas").evaluate("e => e.scrollWidth <= e.clientWidth")
                expect(page.locator("#inventory-warning")).to_contain_text("1 collection error")
                edge = page.locator("#inventory-topology .inventory-edge.forwarding")
                expect(edge).to_have_count(1)
                edge.focus()
                page.keyboard.press("Enter")
                expect(page.locator("#inventory-evidence")).to_contain_text("Synthetic forwarding configuration")
                page.screenshot(path=str(results / "inventory-route.png"))
                nodes.filter(has_text="i-alpha").focus()
                page.keyboard.press("Enter")
                expect(page.locator("#inventory-evidence")).to_contain_text("worker <synthetic>")
                assert page.locator("#inventory-evidence synthetic").count() == 0
                page.screenshot(path=str(results / "inventory-map.png"))
                page.locator('#inventory-views [data-view="systems"]').click()
                expect(page.locator("#inventory-systems-table .tabulator-row")).to_have_count(4)
                holder = page.locator("#inventory-systems-table .tabulator-tableholder")
                assert holder.evaluate("e => { e.scrollLeft = e.scrollWidth; return e.scrollLeft > 0; }")
                expect(page.locator('#inventory-systems-table .tabulator-col[tabulator-field="summary"]')).to_be_in_viewport()
                holder.evaluate("e => { e.scrollLeft = 0; }")
                page.screenshot(path=str(results / "inventory-systems.png"))
                page.locator('#inventory-views [data-view="routes"]').click()
                expect(page.locator("#inventory-routes-table .tabulator-row")).to_have_count(1)
                expect(page.locator("#inventory-routes-table")).to_contain_text("application-gateway")
                page.screenshot(path=str(results / "inventory-routes.png"))
                page.locator('#inventory-views [data-view="groups"]').click()
                expect(page.locator("#inventory-groups-table .tabulator-row")).to_have_count(1)
                page.locator("#inventory-groups-table").get_by_role("button", name="Inspect Application ingress", exact=True).click()
                expect(page.locator("#inventory-evidence")).to_contain_text("Rules alone do not prove a complete internet path")
                page.screenshot(path=str(results / "inventory-groups.png"))
                page.locator('#inventory-views [data-view="systems"]').click()
                page.locator("#inventory-region").select_option("us-east-1")
                expect(page.locator("#inventory-systems-table .tabulator-row")).to_have_count(1)
                page.locator('#inventory-views [data-view="coverage"]').click()
                expect(page.locator("#inventory-coverage-view")).to_contain_text("AccessDenied (synthetic)")
                page.screenshot(path=str(results / "inventory-coverage.png"))
                page.locator("#events-tab").click()
                expect(page.locator("#inventory-panel")).to_be_hidden()
                expect(zone).to_have_value("Asia/Singapore")
                expect(rows).to_have_count(5)
                page.locator("#commands-tab").click()
                expect(page.locator("#commands-panel")).to_be_visible()
                page.locator("#command-list button").first.click()
                system = page.locator("#command-view .reference-trigger").filter(has_text="i-").first
                system.focus()
                expect(card).to_be_visible()
                expect(card).to_contain_text("Source:")
                page.keyboard.press("Escape")

                # Fresh page: API failure is actionable, Retry recovers, absent snapshot is distinct.
                page.reload()
                page.route("**/api/inventory", lambda route: route.fulfill(status=500, body='{"error":"synthetic"}'))
                page.locator("#inventory-tab").click()
                expect(page.locator("#inventory-retry")).to_be_visible()
                page.screenshot(path=str(results / "inventory-error.png"))
                page.unroute("**/api/inventory")
                page.locator("#inventory-retry").click()
                expect(page.locator("#inventory-content")).to_be_visible()
                page.reload()
                page.route("**/api/inventory", lambda route: route.fulfill(json={"loaded": False}))
                page.locator("#inventory-tab").click()
                expect(page.locator("#inventory-status")).to_contain_text("--inventory-export")
                expect(page.locator("#inventory-content")).to_be_hidden()
                page.screenshot(path=str(results / "inventory-absent.png"))
                assert not errors, f"Browser JavaScript errors: {errors}"
                print("PASS: event search/timezone/history, reference cards, inventory map/tables/coverage, tab state, error/retry and no-snapshot; no JavaScript errors.")
            except Exception:
                page.screenshot(path=str(results / "failure.png"))
                raise
            finally:
                context.tracing.stop(path=str(results / "trace.zip"))
                browser.close()
    finally:
        BrowserContract.tearDownClass()


if __name__ == "__main__":
    main()
