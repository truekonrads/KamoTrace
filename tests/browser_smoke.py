"""CI-only browser check; run with `uv run --with playwright==1.64.1 python tests/browser_smoke.py`."""
import copy
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from test_contract import BrowserContract, MFAContract


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

                # Reopening a hybrid API query must retain its external search on Run.
                bounds = page.request.get(BrowserContract.url + "/api/meta").json()
                event = page.request.post(BrowserContract.url + "/api/events", data={}).json()["data"][0]
                hybrid = {"timezone": "Asia/Singapore", "start": bounds["start_ms"], "end": bounds["end_ms"],
                          "pipeline": 'search "ssm.amazonaws.com"', "pipeline_version": 1, "search": "SendCommand"}
                note = page.request.post(BrowserContract.url + "/api/reviews", data={
                    "action": "annotate", "body": "Hybrid query regression", "hashes": [event["record_sha256"]],
                    "context": hybrid}).json()
                page.request.post(BrowserContract.url + "/api/reviews", data={
                    "action": "tag", "slug": "review-race", "color": "#123456", "hashes": [event["record_sha256"]]})
                page.reload()
                expect(rows).to_have_count(5)
                page.locator("#expand-sidebar").click()
                page.locator(".note-head").filter(has_text="Hybrid query regression").click()
                page.get_by_role("button", name="Reopen query", exact=True).click()
                expect(page.locator("#load-status")).to_have_text("3 loaded · all")
                expect(page.locator("#query-state")).to_have_text("Applied")
                with page.expect_response(lambda response: "/api/events" in response.url) as rerun:
                    page.locator("#run").click()
                assert rerun.value.request.post_data_json["search"] == "SendCommand"
                expect(rows).to_have_count(3)
                expect(page.locator("#scopes")).to_contain_text("SendCommand")
                page.screenshot(path=str(results / "pipeline-hybrid-preserved.png"))
                # A single pipeline search plus an external search is not one plain-text query.
                page.locator("#query-mode").select_option("text")
                expect(page.locator("#query-mode")).to_have_value("pipeline")
                expect(page.locator("#pipeline-error")).to_contain_text("cannot be represented")
                expect(page.locator("#search")).to_have_value(hybrid["pipeline"])

                # A shortcut must preserve text entered while validation is pending.
                page.locator("#tags-tab").click()
                with page.expect_response(lambda response: "/api/events" in response.url):
                    page.locator("#run").click()
                blocked = []
                page.route("**/api/pipeline", lambda route: route.continue_() if blocked else blocked.append(route))
                page.locator("#tag-list").get_by_role("button", name="review-race", exact=True).click()
                expect(page.locator("#query-status")).to_have_text("Query in progress")
                page.locator("#search").fill('event_name = "StartSession"')
                for route in blocked:
                    route.continue_()
                expect(page.locator("#pipeline-error")).to_contain_text("Run or Revert")
                page.unroute("**/api/pipeline")
                expect(page.locator("#pipeline-suggestions")).to_be_hidden()
                expect(page.locator("#search")).to_have_value('event_name = "StartSession"')
                expect(page.locator("#query-state")).to_have_text("Draft · Run to apply")
                expect(rows).to_have_count(3)
                page.screenshot(path=str(results / "pipeline-draft-preserved.png"))
                page.locator("#revert").click()

                # Shift+Enter is a newline even with a highlighted completion.
                page.locator("#search").fill("Operation")
                expect(page.get_by_role("option", name="Operation — event_name")).to_be_visible()
                page.locator("#search").press("Shift+Enter")
                expect(page.locator("#search")).to_have_value("Operation\n")
                expect(rows).to_have_count(3)
                page.locator("#search").fill("Operation")
                page.locator("#search").press("Enter")
                expect(page.locator("#search")).to_have_value("event_name ")
                expect(rows).to_have_count(3)
                page.locator("#clear").click()
                expect(page.locator("#load-status")).to_have_text("5 loaded · all")
                page.locator("#collapse-sidebar").click()
                page.request.post(BrowserContract.url + "/api/reviews", data={
                    "action": "delete", "id": note["id"], "updated": note["updated"]})

                # Agent-saved raw filters/projections and array members must survive reopening/editing.
                raw_query = {"start": bounds["start_ms"], "end": bounds["end_ms"], "search": "SendCommand",
                    "raw_fields": ["raw.requestParameters.number"],
                    "filters": [{"field": "raw.sourceIPAddress", "op": "in", "value": ["8.8.8.8", "comma,value"]}]}
                raw_note = page.request.post(BrowserContract.url + "/api/reviews", data={"action": "annotate",
                    "body": "Raw scalar saved query", "hashes": [event["record_sha256"]], "context": raw_query}).json()
                page.reload()
                expect(rows).to_have_count(5)
                page.locator("#expand-sidebar").click()
                page.locator(".note-head").filter(has_text="Raw scalar saved query").click()
                page.get_by_role("button", name="Reopen query", exact=True).click()
                expect(rows).to_have_count(1)
                expect(page.locator("#scopes")).to_contain_text("raw.sourceIPAddress")
                page.locator("#scopes .scope-label").filter(has_text="raw.sourceIPAddress").click()
                expect(page.locator("#filter-field")).to_have_value("raw.sourceIPAddress")
                expect(page.locator("#filter-value")).to_have_value('["8.8.8.8","comma,value"]')
                with page.expect_response(lambda response: "/api/events" in response.url) as raw_response:
                    page.locator("#filter-save").click()
                assert raw_response.value.request.post_data_json["filters"] == raw_query["filters"]
                assert raw_response.value.request.post_data_json["raw_fields"] == raw_query["raw_fields"]
                expect(rows).to_have_count(1)
                page.screenshot(path=str(results / "raw-scalar-query-preserved.png"))
                page.locator("#clear").click()
                expect(rows).to_have_count(5)
                page.locator("#collapse-sidebar").click()
                page.request.post(BrowserContract.url + "/api/reviews", data={
                    "action": "delete", "id": raw_note["id"], "updated": raw_note["updated"]})

                # Context is read-only; focus/click must not open the event row or alter its query.
                identity = rows.first.locator('[tabulator-field="identity"] .cell-text')
                identity.focus()
                card = page.locator("#reference-card")
                expect(card).to_be_visible()
                expect(card).to_contain_text("History not searched")
                expect(card).not_to_contain_text("Observed events")
                page.screenshot(path=str(results / "identity-reference-unsearched.png"))
                with page.expect_response(lambda response: "/api/reference" in response.url) as history:
                    card.get_by_role("button", name="Load event history", exact=True).click()
                assert history.value.request.post_data_json["include_history"] is True
                assert history.value.json()["history_included"] is True
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
                expect(nodes.filter(has_text="i-alpha").locator("image")).to_have_attribute("href", "/vendor/aws-icons/ec2.svg")
                expect(nodes.filter(has_text="lb-synthetic").locator("image")).to_have_attribute("href", "/vendor/aws-icons/elb.svg")
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
                page.screenshot(path=str(results / "inventory-map.png"), full_page=True)
                page.locator("#inventory-open-explorer").click()
                explorer = page.get_by_role("dialog", name="Configuration explorer")
                expect(explorer).to_be_visible()
                expect(page.locator(".inventory-resource-heading img")).to_have_js_property("naturalWidth", 64)
                expect(explorer.locator("#inventory-panel")).to_be_visible()
                expect(page.locator("#inventory-evidence")).to_contain_text("worker <synthetic>")
                canvas = page.locator("#inventory-canvas")
                canvas.focus()
                initial_zoom = page.locator("#inventory-zoom").inner_text()
                page.keyboard.press("+")
                assert page.locator("#inventory-zoom").inner_text() != initial_zoom
                page.keyboard.press("Home")
                expect(page.locator("#inventory-zoom")).to_have_text(initial_zoom)
                box = canvas.bounding_box()
                page.mouse.move(box["x"] + 200, box["y"] + 10)
                page.mouse.wheel(0, -200)
                expect(page.locator("#inventory-zoom")).not_to_have_text(initial_zoom)
                page.mouse.down()
                page.mouse.move(box["x"] + 100, box["y"] + 10, steps=5)
                page.mouse.up()
                assert canvas.evaluate("e => e.scrollLeft > 0")
                page.locator("#inventory-fit-all").click()
                assert canvas.evaluate("e => e.scrollWidth <= e.clientWidth && e.scrollHeight <= e.clientHeight")
                edge.focus()
                page.keyboard.press("Enter")
                expect(page.locator("#inventory-evidence")).to_contain_text("Synthetic forwarding configuration")
                inspector = page.locator("#inventory-inspector")
                assert inspector.evaluate("e => { e.scrollTop = e.scrollHeight; return e.scrollTop > 0; }")
                expect(inspector.get_by_text("Complete collected record", exact=True)).to_be_in_viewport()
                inspector.evaluate("e => { e.scrollTop = 0; }")
                page.screenshot(path=str(results / "inventory-explorer.png"))
                page.locator("#inventory-exposure").select_option("via")
                expect(nodes).to_have_count(1)
                expect(nodes).to_contain_text("i-example")
                page.screenshot(path=str(results / "inventory-explorer-filtered.png"))
                page.locator("#inventory-close-explorer").click()
                expect(explorer).not_to_be_visible()
                expect(page.locator("#inventory-exposure")).to_have_value("via")
                expect(nodes).to_have_count(1)
                page.locator("#inventory-open-explorer").click()
                page.set_viewport_size({"width": 1280, "height": 800})
                inspector_box = page.locator("#inventory-inspector").bounding_box()
                assert inspector_box["y"] + inspector_box["height"] <= 800
                page.locator("#inventory-fit").click()
                page.screenshot(path=str(results / "inventory-explorer-short.png"))
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.locator('#inventory-views [data-view="systems"]').click()
                expect(page.locator("#inventory-systems-table .tabulator-row")).to_have_count(1)
                table_zoom = page.locator("#inventory-zoom").inner_text()
                page.locator("#inventory-close-explorer").click()
                page.locator("#inventory-open-explorer").click()
                expect(page.locator("#inventory-zoom")).to_have_text(table_zoom)
                page.locator('#inventory-views [data-view="map"]').click()
                page.locator("#inventory-exposure").select_option("direct")
                expect(nodes).to_have_count(3)
                expect(nodes.filter(has_text="i-example")).to_have_count(0)
                page.locator("#inventory-search").fill("no-such-synthetic-resource")
                expect(nodes).to_have_count(0)
                expect(page.locator("#inventory-topology")).to_contain_text("No matching collected systems")
                page.screenshot(path=str(results / "inventory-explorer-empty.png"))
                page.locator("#inventory-clear").click()
                expect(nodes).to_have_count(4)
                page.keyboard.press("Escape")
                expect(explorer).not_to_be_visible()
                expect(page.locator("#inventory-open-explorer")).to_be_focused()
                expect(nodes).to_have_count(4)
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

                # Global IAM ignores the active network Region filter and retains policy provenance.
                page.locator('#inventory-views [data-view="iam"]').click()
                iam_table = page.locator("#inventory-iam-table")
                expect(iam_table.locator(".tabulator-row")).to_have_count(1)
                expect(iam_table).to_contain_text("Active key ≥90 days old")
                expect(iam_table).to_contain_text("1 active / 2 recorded keys")
                expect(iam_table).to_contain_text("2026-10-27T12:30:00Z")
                for field in ("review", "activity"):
                    cell = iam_table.locator(f'.tabulator-row [tabulator-field="{field}"]')
                    assert cell.evaluate("e => e.scrollHeight <= e.clientHeight + 1"), f"Clipped IAM {field}"
                iam_table.get_by_role("button", name="Inspect analyst", exact=True).click()
                inspector = page.locator("#inventory-evidence")
                review = inspector.locator(".iam-review")
                expect(inspector.locator(".reference-iam-summary")).to_contain_text("investigators")
                expect(review).to_contain_text("Active key ≥90 days old")
                expect(review).to_contain_text("investigators / CaseRead")
                expect(review).to_contain_text("Action s3:*")
                expect(review).not_to_contain_text("Action *;")  # Non-default versions are not grants.
                expect(review).not_to_contain_text("s3:DeleteObject")  # Denies are not allow signals.
                expect(review).not_to_contain_text("AKIASYNTHETICKEY2")  # Inactive keys are not stale active keys.
                inspector.get_by_role("button", name="Load CloudTrail MFA evidence", exact=True).click()
                expect(inspector.locator(".reference-mfa-history")).to_contain_text("No matching CloudTrail events")
                page.screenshot(path=str(results / "inventory-iam-users.png"))
                page.locator("#inventory-evidence .reference-trigger").click()
                expect(card).to_contain_text("Group membership")
                expect(card.locator(".iam-review")).to_have_text(review.text_content())
                card.locator(".iam-review").get_by_text("Active key ≥90 days old", exact=True).click()
                page.screenshot(path=str(results / "iam-user-risk.png"))
                summary = card.locator(".reference-iam-summary")
                expect(summary).to_contain_text("investigators")
                expect(summary).to_contain_text("investigators: inline-group, CaseRead")
                expect(summary).to_contain_text("inline-user")
                expect(summary).to_contain_text("2026-10-27T12:30:00Z")
                expect(summary).to_contain_text("2 recorded")
                page.screenshot(path=str(results / "iam-user-summary.png"))
                keys = card.locator(".reference-access-key")
                expect(keys).to_have_count(2)
                keys.first.locator("summary").click()
                expect(keys.first).to_contain_text("2026-10-28T04:10:00Z")
                expect(keys.first).to_contain_text("s3")
                expect(keys.first).to_contain_text("ap-southeast-1")
                keys.last.locator("summary").click()
                expect(keys.last).to_contain_text("Inactive")
                expect(keys.last).to_contain_text("No last-use timestamp reported by AWS")
                page.screenshot(path=str(results / "iam-access-key-activity.png"))
                expect(card).to_contain_text("CaseRead (Customer managed)")
                card.get_by_text("Inline: inline-group", exact=True).click()
                expect(card).to_contain_text("s3:DeleteObject")
                page.screenshot(path=str(results / "iam-user-card.png"))
                page.keyboard.press("Escape")
                page.locator("#inventory-iam-collection").select_option("roles")
                expect(iam_table).to_contain_text("Wildcard trust principal")
                expect(iam_table).to_contain_text("Cross-account trust")
                iam_table.get_by_role("button", name="Inspect auditor", exact=True).click()
                expect(review.locator("summary").filter(has_text="Wildcard trust principal")).to_have_count(1)
                expect(review).not_to_contain_text("Broad action allow")  # Boundaries do not grant permissions.
                expect(review).to_contain_text("AWS-managed metadata only")
                page.locator("#inventory-evidence .reference-trigger").click()
                expect(card).to_contain_text("ReadOnlyAccess (AWS managed; metadata only)")
                expect(summary).to_contain_text("IAM role")
                expect(summary).to_contain_text("auditor")
                expect(summary).to_contain_text("2026-10-28T09:15:00Z")
                expect(summary).to_contain_text("ap-southeast-1")
                card.locator(".iam-review").get_by_text("Cross-account trust", exact=True).click()
                expect(card.locator(".iam-review")).to_contain_text("Conditions are present")
                expect(card.locator(".iam-review")).to_contain_text("arn:aws:iam::456:root")
                page.screenshot(path=str(results / "iam-role-summary.png"))
                card.get_by_text("Trust policy", exact=True).click()
                expect(card).to_contain_text("sts:AssumeRole")
                expect(card).to_contain_text("Permissions boundary")
                page.screenshot(path=str(results / "iam-role-card.png"))
                page.keyboard.press("Escape")
                page.locator("#inventory-iam-collection").select_option("groups")
                iam_table.get_by_role("button", name="Inspect investigators", exact=True).click()
                page.locator("#inventory-evidence .reference-trigger").click()
                expect(card).to_contain_text("Collected group members")
                expect(card).to_contain_text("arn:aws:iam::123:user/team/analyst")
                page.screenshot(path=str(results / "iam-group-card.png"))
                page.keyboard.press("Escape")
                page.locator("#inventory-iam-collection").select_option("policies")
                expect(iam_table.locator(".tabulator-row")).to_have_count(2)
                iam_table.get_by_role("button", name="Inspect CaseRead", exact=True).click()
                expect(page.locator("#inventory-evidence")).to_contain_text('"IsDefaultVersion": true')
                page.screenshot(path=str(results / "inventory-iam-custom-policy.png"))
                page.locator("#inventory-iam-collection").select_option("aws_managed_policies")
                iam_table.get_by_role("button", name="Inspect ReadOnlyAccess", exact=True).click()
                expect(page.locator("#inventory-evidence")).to_contain_text("Policy documents were not collected")
                expect(page.locator("#inventory-evidence")).not_to_contain_text("PolicyVersionList")
                page.screenshot(path=str(results / "inventory-iam-aws-policy.png"))
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

                # Collection-time boundaries and unknowns must not become "unused" or "safe".
                snapshot = context.request.get(BrowserContract.url + "/api/inventory").json()
                variant = context.new_page()
                variant.on("pageerror", lambda error: errors.append(str(error)))
                for scenario in ("boundary", "partial", "legacy"):
                    report = copy.deepcopy(snapshot)
                    user = report["iam"]["users"][0]
                    activity = user["activity"]
                    if scenario == "boundary":
                        key = activity["access_keys"][0]
                        key["CreateDate"] = "2026-07-31T15:02:00Z"  # Exactly 90 days before collection.
                        key["last_used"]["LastUsedDate"] = "2026-07-31T15:02:00Z"
                        recent = copy.deepcopy(key)
                        recent.update(AccessKeyId="AKIARECENT89DAYS", CreateDate="2026-08-01T15:02:00Z")
                        recent["last_used"]["LastUsedDate"] = "2026-08-01T15:02:00Z"
                        activity["access_keys"].append(recent)
                    elif scenario == "partial":
                        activity.update(console_status="unknown", access_keys_status="unknown")
                        activity["access_keys"][0].update(last_used_status="unknown", last_used={})
                    else:
                        del user["activity"]
                    variant.route("**/api/inventory", lambda route: route.fulfill(json=report))
                    variant.goto(BrowserContract.url)
                    expect(variant.locator("#load-status")).to_have_text("5 loaded · all")
                    variant.locator("#inventory-tab").click()
                    variant.locator('#inventory-views [data-view="iam"]').click()
                    variant.locator("#inventory-iam-table").get_by_role("button", name="Inspect analyst", exact=True).click()
                    evidence = variant.locator("#inventory-evidence")
                    checks = evidence.locator(".iam-review")
                    if scenario == "boundary":
                        expect(checks).to_contain_text("Active key last used ≥90 days ago")
                        expect(checks).to_contain_text("90 days old at collection")
                        expect(checks).not_to_contain_text("AKIARECENT89DAYS")
                        expect(checks).not_to_contain_text("AKIASYNTHETICKEY2")
                    else:
                        expect(checks).to_contain_text("Credential coverage gap")
                        expect(checks).not_to_contain_text("Active key usage unreported")
                        expect(evidence.locator(".reference-iam-summary")).to_contain_text("incomplete" if scenario == "partial" else "Not collected")
                        if scenario == "partial":
                            expect(checks).to_contain_text("Key usage unknown")
                        variant.screenshot(path=str(results / f"iam-{scenario}.png"))
                    variant.unroute("**/api/inventory")
                variant.close()

                MFAContract.setUpClass()
                try:
                    mfa_page = context.new_page()
                    mfa_page.on("pageerror", lambda error: errors.append(str(error)))
                    mfa_page.goto(MFAContract.url)
                    expect(mfa_page.locator("#load-status")).to_have_text("14 loaded · all")
                    mfa_page.locator("#inventory-tab").click()
                    mfa_page.locator('#inventory-views [data-view="iam"]').click()
                    mfa_page.get_by_role("button", name="Inspect analyst", exact=True).click()
                    mfa_inspector = mfa_page.locator("#inventory-evidence")
                    expect(mfa_inspector.locator(".reference-iam-summary")).to_contain_text("1 enrolled devices at collection")
                    expect(mfa_inspector.locator(".reference-iam-summary")).to_contain_text("Login profile present")
                    expect(mfa_inspector.locator(".iam-review")).not_to_contain_text("Console password with no enrolled MFA")
                    mfa_inspector.get_by_role("button", name="Load CloudTrail MFA evidence", exact=True).click()
                    observations = mfa_inspector.locator(".reference-mfa-history")
                    expect(observations.locator(".reference-mfa-observation")).to_have_count(2)
                    observations.locator(".reference-mfa-observation > summary").filter(has_text="9 events").click()
                    expect(observations).to_contain_text("2026-10-01 00:00:00+00")
                    expect(observations).to_contain_text("successful console sign-ins explicitly reported MFAUsed=No")
                    us_observation = observations.locator(".reference-mfa-observation").filter(has_text="9 events")
                    expect(us_observation.get_by_text("Failed / unknown-result sign-ins", exact=True).locator("xpath=following-sibling::dd[1]")).to_have_text("2")
                    observations.screenshot(path=str(results / "iam-mfa-observed.png"))
                    mfa_inspector.locator(".reference-trigger").click()
                    mfa_card = mfa_page.locator("#reference-card")
                    mfa_card.get_by_role("button", name="Load CloudTrail MFA evidence", exact=True).click()
                    expect(mfa_card.locator(".reference-mfa-observation")).to_have_count(2)
                    mfa_card.locator(".reference-mfa-observation > summary").filter(has_text="9 events").click()
                    expect(mfa_card).to_contain_text("MFA enrollment")
                    mfa_card.locator(".reference-mfa-history").screenshot(path=str(results / "iam-mfa-card.png"))
                    without_mfa = mfa_page.request.get(MFAContract.url + "/api/inventory").json()
                    without_mfa["iam"]["users"][0]["activity"]["mfa_devices"] = []
                    mfa_page.route("**/api/inventory", lambda route: route.fulfill(json=without_mfa))
                    mfa_page.reload()
                    expect(mfa_page.locator("#load-status")).to_have_text("14 loaded · all")
                    mfa_page.locator("#inventory-tab").click()
                    mfa_page.locator('#inventory-views [data-view="iam"]').click()
                    mfa_page.get_by_role("button", name="Inspect analyst", exact=True).click()
                    expect(mfa_inspector.locator(".iam-review")).to_contain_text("Console password with no enrolled MFA")
                    mfa_page.close()
                finally:
                    MFAContract.tearDownClass()

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
                # Let the initial sidebar frame run after startup's API reads, but
                # before grid initialization. A constructed grid is not yet ready.
                page.add_init_script("""
                    const schedule = window.setTimeout.bind(window);
                    const animate = window.requestAnimationFrame.bind(window);
                    window.setTimeout = (callback, delay = 0, ...args) =>
                        schedule(callback, delay === 0 ? 500 : delay, ...args);
                    window.requestAnimationFrame = callback =>
                        animate(time => schedule(() => callback(time), 100));
                """)
                page.reload()
                expect(page.locator("#load-status")).to_have_text("5 loaded · all")
                page.locator("#expand-sidebar").click()
                expect(page.locator("#sidebar-panel")).to_be_visible()
                page.locator("#collapse-sidebar").click()
                expect(page.locator("#rail")).to_be_visible()
                expect(rows).to_have_count(5)
                assert not errors, f"Browser JavaScript errors: {errors}"
                print("PASS: event search/timezone/history, hybrid pipeline scopes, shortcut draft races, autocomplete/newlines, reference cards, inventory map/tables/coverage, tab state, error/retry and no-snapshot; no JavaScript errors.")
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
