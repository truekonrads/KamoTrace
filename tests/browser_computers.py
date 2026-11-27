"""Run with uv run --with playwright==1.64.1 python tests/browser_computers.py."""
from pathlib import Path
import re

from playwright.sync_api import expect, sync_playwright

from test_computers import ComputerContract, cloud, dataset
from test_contract import inventory_fixture


def main():
    results = Path("test-results")
    results.mkdir(exist_ok=True)
    fixture = ComputerContract()
    fixture.setUp()
    try:
        first = dataset(fixture.root, "one", [
            {"host": {"id": "machine-A", "name": "shared", "ip": ["10.0.1.5", "2001:db8::5", "192.0.2.9"], "uptime": 7200, "os": {"version": "v1"}}, "cloud": cloud()},
            {"host": {"id": "machine-A", "name": "renamed", "uptime": 9000, "os": {"version": "v2"}}, "cloud": cloud()},
            {"host": {"id": "machine-B", "name": "shared", "uptime": 90061}},
            {"host": {"name": "<img src=x onerror=alert(1)>"}, "cloud": cloud()},
            {}, {"host": {"id": "no-match"}, "cloud": cloud(account="999")},
        ])
        second = dataset(fixture.root, "two", [{"host": {"name": "synthetic"}, "source": {"ip": "192.0.2.8"}}, {}])
        empty = dataset(fixture.root, "empty", [])
        inventory_fixture(fixture.root / "inventory")
        fixture.start(first, other_events=[second, empty], inventory_export=fixture.root / "inventory")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=2)
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                context_requests = []
                page.on("request", lambda request: context_requests.append(request.url) if request.url.endswith("/api/computers") else None)
                page.goto(fixture.url)
                expect(page.locator("#load-status")).to_have_text("8 loaded · all")
                assert not context_requests, "Collapsed cards must not start historical scans"
                summary = page.locator("#computer-imports > summary")
                summary.click()
                cards = page.locator(".computer-card")
                expect(cards).to_have_count(4)
                expect(cards.first).to_contain_text("Multiple / conflicting values")
                expect(cards.first.get_by_role("button", name="2h", exact=True)).to_have_attribute("title", re.compile("7200 seconds"))
                expect(cards.first.get_by_role("button", name="2h 30m", exact=True)).to_be_visible()
                expect(cards.nth(1)).to_contain_text("1d 1h 1m 1s")
                expect(cards.nth(1)).to_contain_text("machine-B")
                expect(cards.nth(2)).to_contain_text("<img src=x onerror=alert(1)>")
                assert cards.locator("img").count() == 0
                # Inventory stays compact; secondary facts and additional values remain accessible.
                expect(cards.first.get_by_text("Host ID", exact=True)).to_be_hidden()
                expect(cards.first.get_by_role("button", name="192.0.2.9", exact=True)).to_be_hidden()
                cards.first.get_by_text("More values (1)", exact=True).click()
                expect(cards.first.get_by_role("button", name="192.0.2.9", exact=True)).to_be_visible()
                cards.first.get_by_text("More values (1)", exact=True).click()
                expect(cards.first.get_by_text("· Additional conflicting values", exact=True)).to_be_visible()
                expect(cards.first.get_by_role("button", name="v1", exact=True)).to_be_hidden()
                details = cards.first.get_by_text(re.compile("^Details & provenance"))
                details.click()
                expect(cards.first.get_by_text("Host ID", exact=True)).to_be_visible()
                expect(cards.first.get_by_role("button", name="v1", exact=True)).to_be_visible()
                expect(cards.first).to_contain_text("inventory is a separate snapshot")
                details.press("Enter")
                expect(cards.first.get_by_text("Host ID", exact=True)).to_be_hidden()
                zone = page.get_by_role("combobox", name="Timezone", exact=True)
                zone.fill("Asia/Singapore")
                zone.press("Tab")
                expect(cards.first).to_contain_text("2021-03-09T20:00:00 Asia/Singapore")
                expect(page.locator("#computer-import-select option:checked")).to_contain_text("Asia/Singapore")
                expect(page.get_by_role("button", name="Inventory snapshot: i-example", exact=True)).to_have_count(1)
                page.get_by_role("button", name="Inventory snapshot: i-example", exact=True).click()
                expect(page.locator("#reference-card")).to_contain_text("Account: 123")
                expect(page.locator("#reference-card")).to_contain_text("ap-southeast-3")
                page.locator("#reference-card").get_by_role("button", name="Close", exact=True).click()
                cards.first.get_by_role("button", name="2h", exact=True).click()
                expect(page.locator("#reference-card")).to_be_hidden()
                expect(page.locator("#raw-event")).to_contain_text('"uptime": 7200')
                expect(page.locator("#event-provenance")).to_contain_text("case-one")
                expect(page.locator("#detail-findings").get_by_role("button", name="Edit tags…", exact=True)).to_be_visible()
                expect(page.locator("#detail-findings").get_by_role("button", name="Add to finding…", exact=True)).to_be_visible()
                page.locator("#detail-next").click()
                expect(page.locator("#raw-event")).to_contain_text('"uptime": 9000')
                page.locator("#close-detail").click()
                page.locator("#search").fill("no-match")
                page.locator("#search").press("Enter")
                expect(page.locator("#load-status")).to_have_text("1 loaded · all")
                cards.first.get_by_role("button", name="2h", exact=True).click()
                expect(page.locator("#detail-next")).to_be_hidden()
                page.keyboard.press("j")
                expect(page.locator("#raw-event")).to_contain_text('"uptime": 7200')
                page.locator("#detail-findings").get_by_role("button", name="Edit tags…", exact=True).click()
                page.locator("#tag-slug").fill("card-reviewed")
                page.locator("#create-tag").click()
                expect(page.locator("#detail-findings")).to_contain_text("card-reviewed")
                page.locator("#detail-title").click()
                page.locator("#detail-findings").get_by_role("button", name="Add to finding…", exact=True).click()
                expect(page.locator("#new-note")).to_be_visible()
                page.locator("#detail-title").click()
                page.locator("#close-detail").click()
                expect(page.locator("#load-status")).to_have_text("1 loaded · all")
                page.locator("#search").fill("")
                page.locator("#search").press("Enter")
                expect(page.locator("#load-status")).to_have_text("8 loaded · all")
                summary.scroll_into_view_if_needed()
                page.screenshot(path=str(results / "computer-multiple.png"))
                page.locator("#computer-next").click()
                expect(cards).to_have_count(1)
                expect(cards).to_contain_text("AWS: no_match")
                page.locator("#computer-import-select").select_option("1")
                expect(cards).to_have_count(2)
                expect(cards.first).to_contain_text("Unavailable in parsed evidence")
                expect(cards.first).not_to_contain_text("192.0.2.8")
                summary.scroll_into_view_if_needed()
                page.screenshot(path=str(results / "computer-unavailable.png"))
                page.locator("#computer-import-select").select_option("2")
                expect(cards).to_have_count(1)
                expect(cards).to_contain_text("Unbound observations")
                expect(page.locator("#computer-import-status")).to_contain_text("0 / 0")
                # A failed import selection must not leave previous cards masquerading as the result.
                page.route("**/api/computers", lambda route: route.fulfill(status=500, content_type="application/json", body='{"error":"Synthetic summary failure"}'))
                page.locator("#computer-import-select").select_option("0")
                expect(page.locator("#computer-import-status")).to_contain_text("Synthetic summary failure")
                expect(cards).to_have_count(0)
                page.unroute("**/api/computers")
                summary.click()
                summary.click()
                expect(cards).to_have_count(4)
                pending = []
                page.route("**/api/computers", lambda route: pending.append(route) if route.request.post_data_json.get("dataset_index") == 0 else route.continue_())
                summary.click()
                summary.click()
                expect(page.locator("#computer-import-status")).to_contain_text("Loading acquired computer context")
                page.locator("#computer-import-select").select_option("1")
                expect(cards).to_have_count(2)
                assert pending
                with page.expect_response(lambda response: response.url.endswith("/api/computers") and response.request.post_data_json.get("dataset_index") == 0):
                    pending.pop().continue_()
                page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
                expect(cards).to_have_count(2)
                expect(cards.first).to_contain_text("synthetic")
                expect(page.locator("#load-status")).to_have_text("8 loaded · all")
                assert not errors, errors
                print("PASS: multiple imports/computers, conflicts, historical basics, missing/empty, plaintext safety, exact AWS reference, original evidence navigation, pagination, failure recovery and stale responses; timeline unchanged")
            finally:
                browser.close()
    finally:
        fixture.doCleanups()


def undated_only():
    fixture = ComputerContract()
    fixture.setUp()
    try:
        primary = dataset(fixture.root, "undated", [{"@timestamp": None, "host": {"id": "unknown-time"}}])
        fixture.start(primary)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=2)
                page.goto(fixture.url)
                expect(page.locator("#load-status")).to_have_text("1 loaded · all")
                expect(page.locator("#coverage")).to_contain_text("1 undated · No selected timestamps")
                page.locator("#search").fill("unknown-time")
                page.locator("#search").press("Enter")
                expect(page.locator("#load-status")).to_have_text("1 loaded · all")
                expect(page.locator("#coverage")).to_contain_text("No selected timestamps")
                zone = page.get_by_role("combobox", name="Timezone", exact=True)
                zone.fill("Asia/Singapore")
                with page.expect_response(lambda response: response.url.endswith("/api/events")
                    and response.request.method == "POST"
                    and response.request.post_data_json.get("timezone") == "Asia/Singapore"):
                    zone.press("Tab")
                expect(page.locator("#app-loading")).to_be_hidden()
                expect(page.locator("#coverage")).to_contain_text("1 undated · No selected timestamps")
                expect(page.locator("#coverage")).not_to_contain_text("1970")
                expect(page.locator("#start")).to_have_value("")
                expect(page.locator("#end")).to_have_value("")
                expect(page.locator("#time-slider")).to_be_hidden()
                expect(page.get_by_role("button", name="Undated observations · no time range", exact=True)).to_be_visible()
                expect(page.locator("#query-state")).to_have_text("Applied")
                expect(page.locator("#range-duration")).to_have_text("Undated observations · no time range")
                page.get_by_role("checkbox", name="Select all loaded events", exact=True).click()
                page.locator("#add-to-note").click()
                page.locator("#new-note").click()
                expect(page.locator("#review-context")).to_contain_text("Undated observations · no time range")
                expect(page.locator("#review-context")).not_to_contain_text("1970")
                page.keyboard.press("Escape")
                page.locator("#toggle-charts").click()
                page.locator("#computer-imports > summary").click()
                expect(page.locator(".computer-card")).to_contain_text("unknown-time")
                page.screenshot(path="test-results/computer-undated.png")
                print("PASS: undated-only search/timezone retains unknown coverage, no invented 1970 range")
            finally:
                browser.close()
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    main()
    undated_only()
