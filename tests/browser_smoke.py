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
                page.goto(BrowserContract.url)
                rows = page.locator("#events .tabulator-row")
                expect(page.locator("#load-status")).to_have_text("5 loaded · all", timeout=30000)
                expect(rows).to_have_count(5)
                expect(page.locator("#coverage")).to_contain_text("5 events")
                page.screenshot(path=str(results / "events.png"))

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
                assert not errors, f"Browser JavaScript errors: {errors}"
                print("PASS: event search, timezone refresh, validation, history and persistence; no JavaScript errors.")
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
