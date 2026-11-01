"""Recorded event/failure volume spikes within an identity's observed windows."""
from ._analysis import MIN_REFERENCE_WINDOWS, ROBUST_THRESHOLD, link_signals, score_windows

ID = "kamotrace:volume-spike"
VERSION = 1
TITLE = "KamoTrace: Recorded event or failure volume spike"
LEVEL = "low"
TACTICS = []
TECHNIQUES = []


def run(connection, context=None):
    windows = {(actor, dimension): buckets for actor, dimension, buckets in connection.execute("""
        SELECT actor, dimension, list(DISTINCT bucket) FROM analysis_dimensions GROUP BY actor, dimension""").fetchall()}
    rows = connection.execute("""SELECT actor, dimension, value, bucket, count(*) AS events,
        count(*) FILTER (WHERE failed) AS failures FROM analysis_dimensions
        GROUP BY actor, dimension, value, bucket""").fetchall()
    signals, insufficient = [], 0
    for metric, index, minimum in (("events", 4, 10), ("failures", 5, 5)):
        found, skipped = score_windows(
            [(row[0], row[1], row[2], metric, row[3], row[index]) for row in rows], windows, minimum, 3)
        signals.extend(found)
        insufficient += skipped
    for _, bucket, _, _, _, details in signals:
        details["window_start_epoch"] = bucket
        details["reason"] = "Recorded count exceeds robust reference and fold thresholds"
    matches = link_signals(connection, signals)
    return matches, {"status": "completed", "matched_groups": len(signals), "matches": len(matches),
        "insufficient_reference_candidates": insufficient, "minimum_reference_windows": MIN_REFERENCE_WINDOWS,
        "minimum_robust_score": ROBUST_THRESHOLD, "minimum_events": 10, "minimum_failures": 5,
        "minimum_fold": 3, "zero_policy": "only windows with recorded activity and known dimension"}
