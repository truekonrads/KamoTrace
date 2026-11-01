"""Distinct-operation/service/region/resource breadth, independent of call volume."""
from ._analysis import MIN_REFERENCE_WINDOWS, ROBUST_THRESHOLD, link_signals, score_windows

ID = "kamotrace:breadth-spike"
VERSION = 1
TITLE = "KamoTrace: Recorded operation or resource breadth spike"
LEVEL = "low"
TACTICS = []
TECHNIQUES = []


def run(connection, context=None):
    rows = connection.execute("""WITH values AS (
        SELECT actor, bucket, 'operations' AS metric, operation AS value FROM analysis_events
        UNION ALL SELECT actor, bucket, 'services', event_source FROM analysis_events
        UNION ALL SELECT actor, bucket, 'regions', aws_region FROM analysis_events
        UNION ALL SELECT e.actor, e.bucket, 'resources', j.value->>'$.ARN'
            FROM analysis_events e, json_each(e.resources) j
    ) SELECT actor, metric, bucket, count(DISTINCT value) FROM values
        WHERE value IS NOT NULL AND value <> '' GROUP BY actor, metric, bucket""").fetchall()
    windows = {}
    series = []
    for actor, metric, bucket, count in rows:
        windows.setdefault((actor, metric), []).append(bucket)
        series.append((actor, metric, metric, metric, bucket, count))
    signals, insufficient = score_windows(series, windows, 5, 3)
    # These signals describe breadth of the whole recorded window, not individual API risk.
    for index, (actor, bucket, dimension, value, failed, details) in enumerate(signals):
        details["window_start_epoch"] = bucket
        details["reason"] = f"Distinct {dimension} exceed robust reference and fold thresholds"
        signals[index] = (actor, bucket, "breadth", value, failed, details)
    matches = link_signals(connection, signals)
    return matches, {"status": "completed", "matched_groups": len(signals), "matches": len(matches),
        "insufficient_reference_candidates": insufficient, "minimum_reference_windows": MIN_REFERENCE_WINDOWS,
        "minimum_robust_score": ROBUST_THRESHOLD, "minimum_distinct": 5, "minimum_fold": 3}
