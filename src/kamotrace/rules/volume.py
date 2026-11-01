"""Recorded event/failure volume spikes within an identity's observed windows."""
from itertools import groupby

from ._analysis import MIN_REFERENCE_WINDOWS, ROBUST_THRESHOLD, link_signals, ordered_rows, score_windows

ID = "kamotrace:volume-spike"
VERSION = 1
TITLE = "KamoTrace: Recorded event or failure volume spike"
LEVEL = "low"
TACTICS = []
TECHNIQUES = []


def run(connection, context=None, *, bucket_minutes=5):
    insufficient = 0

    def signals():
        nonlocal insufficient
        rows = ordered_rows(connection, """SELECT actor, dimension, value, bucket, count(*) AS events,
            count(*) FILTER (WHERE failed) AS failures FROM analysis_dimensions
            GROUP BY actor, dimension, value, bucket ORDER BY actor, dimension, value, bucket""")
        for (actor, dimension), group in groupby(rows, lambda row: row[:2]):
            group = list(group)
            # A value absent in a window is zero, including windows containing another value.
            windows = {row[3] for row in group}
            for value, series in groupby(group, lambda row: row[2]):
                series = list(series)
                for metric, index, minimum in (("events", 4, 10), ("failures", 5, 5)):
                    found, skipped = score_windows({row[3]: row[index] for row in series}, windows, minimum, 3)
                    insufficient += skipped
                    for bucket, details in found:
                        details.update(dimension=dimension, value=value, metric=metric, window_start_epoch=bucket,
                            reason="Recorded count exceeds robust reference and fold thresholds")
                        yield actor, bucket, dimension, value, metric == "failures", details

    matches, groups = link_signals(connection, signals(), ID, bucket_minutes)
    return {"status": "completed", "matched_groups": groups, "matches": matches,
        "insufficient_reference_candidates": insufficient, "minimum_reference_windows": MIN_REFERENCE_WINDOWS,
        "minimum_robust_score": ROBUST_THRESHOLD, "minimum_events": 10, "minimum_failures": 5,
        "minimum_fold": 3, "zero_policy": "only windows with recorded activity and known dimension"}
