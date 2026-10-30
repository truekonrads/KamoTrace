"""CI-only browser check; run with `uv run --with playwright==1.58.0 python tests/browser_smoke.py`."""
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
                expect(page.locator("#load-status")).to_have_text("5 loaded · all")
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
                assert not errors, f"Browser JavaScript errors: {errors}"
                print("PASS: five events rendered; search returned exactly three SendCommand rows; no JavaScript errors.")
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
