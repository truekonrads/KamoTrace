"""Distinct-operation/service/region/resource breadth, independent of call volume."""
from itertools import groupby

from ._analysis import MIN_REFERENCE_WINDOWS, ROBUST_THRESHOLD, link_signals, ordered_rows, score_windows

ID = "kamotrace:breadth-spike"
VERSION = 1
TITLE = "KamoTrace: Recorded operation or resource breadth spike"
LEVEL = "low"
TACTICS = []
TECHNIQUES = []


def run(connection, context=None, *, bucket_minutes=5):
    insufficient = 0

    def signals():
        nonlocal insufficient
        rows = ordered_rows(connection, """WITH values AS (
        SELECT actor, bucket, 'operations' AS metric, operation AS value FROM analysis_events
        UNION ALL SELECT actor, bucket, 'services', event_source FROM analysis_events
        UNION ALL SELECT actor, bucket, 'regions', aws_region FROM analysis_events
        UNION ALL SELECT e.actor, e.bucket, 'resources', j.value->>'$.ARN'
            FROM analysis_events e, json_each(e.resources) j
    ) SELECT actor, metric, bucket, count(DISTINCT value) FROM values
        WHERE value IS NOT NULL AND value <> '' GROUP BY actor, metric, bucket
        ORDER BY actor, metric, bucket""")
        for (actor, metric), series in groupby(rows, lambda row: row[:2]):
            counts = {bucket: count for _, _, bucket, count in series}
            # Metric-unknown windows are absent, not zero breadth.
            found, skipped = score_windows(counts, counts, 5, 3)
            insufficient += skipped
            for bucket, details in found:
                details.update(dimension=metric, value=metric, metric=metric, window_start_epoch=bucket,
                    reason=f"Distinct {metric} exceed robust reference and fold thresholds")
                # Breadth describes the whole recorded window, not individual API risk.
                yield actor, bucket, "breadth", metric, False, details

    matches, groups = link_signals(connection, signals(), ID, bucket_minutes)
    return {"status": "completed", "matched_groups": groups, "matches": matches,
        "insufficient_reference_candidates": insufficient, "minimum_reference_windows": MIN_REFERENCE_WINDOWS,
        "minimum_robust_score": ROBUST_THRESHOLD, "minimum_distinct": 5, "minimum_fold": 3}
