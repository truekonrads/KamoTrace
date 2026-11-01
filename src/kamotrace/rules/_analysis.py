"""Shared robust window statistics and exact member linkage for offline analyses."""
from collections import defaultdict
import json
from statistics import median

MIN_REFERENCE_WINDOWS = 8
ROBUST_THRESHOLD = 6


def score_windows(rows, windows, minimum, ratio):
    """Leave the scored window out; zeros exist only in otherwise observed windows."""
    groups = defaultdict(dict)
    for actor, dimension, value, metric, bucket, observed in rows:
        groups[(actor, dimension, value, metric)][bucket] = observed
    signals, insufficient = [], 0
    for (actor, dimension, value, metric), counts in groups.items():
        observed_windows = windows.get((actor, dimension), [])
        reference_size = len(observed_windows) - 1
        summaries = {}
        for bucket, observed in counts.items():
            if observed < minimum:
                continue
            if reference_size < MIN_REFERENCE_WINDOWS:
                insufficient += 1
                continue
            # Equal counts have the same leave-one-out reference distribution.
            if observed not in summaries:
                reference = [counts.get(other, 0) for other in observed_windows if other != bucket]
                center = median(reference)
                summaries[observed] = center, median(abs(n - center) for n in reference)
            center, mad = summaries[observed]
            scale = max(1.0, 1.4826 * mad)
            score = (observed - center) / scale
            fold = observed / max(1.0, center)
            if score >= ROBUST_THRESHOLD and fold >= ratio:
                signals.append((actor, bucket, dimension, value, metric == "failures", {
                    "dimension": dimension, "value": value, "metric": metric,
                    "observed": observed, "reference_windows": reference_size,
                    "reference_median": center, "reference_mad": mad,
                    "robust_score": score, "fold_over_reference_floor_one": fold,
                    "minimum_observed": minimum, "minimum_fold": ratio,
                    "minimum_robust_score": ROBUST_THRESHOLD,
                    "baseline_mode": "retrospective, other observed windows; scored window excluded"}))
    return signals, insufficient


def link_signals(connection, signals):
    """Link group/window leads to their actual members, never to guessed events."""
    if not signals:
        return []
    connection.execute("""CREATE OR REPLACE TEMP TABLE analysis_signals(actor VARCHAR, bucket BIGINT,
        dimension VARCHAR, value VARCHAR, failures_only BOOLEAN, details JSON)""")
    connection.executemany("INSERT INTO analysis_signals VALUES (?, ?, ?, ?, ?, ?)",
        [(actor, bucket, dimension, value, failed, json.dumps({**details, "identity": json.loads(actor)}))
         for actor, bucket, dimension, value, failed, details in signals])
    rows = connection.execute("""SELECT e.source_record, e.record_sha256, list(s.details::VARCHAR)
        FROM analysis_events e JOIN analysis_signals s ON e.actor=s.actor
            AND (s.bucket IS NULL OR e.bucket=s.bucket)
            AND (NOT s.failures_only OR e.failed)
            AND CASE s.dimension WHEN 'operation' THEN e.operation=s.value
                WHEN 'asn' THEN e.asn=s.value WHEN 'country' THEN e.country=s.value ELSE true END
        GROUP BY e.source_record, e.record_sha256 ORDER BY e.source_record""").fetchall()
    return [(record, digest, {"signals": [json.loads(s) for s in details],
             "link_basis": "exact member of the scored recorded group/window; not proof of malicious activity"})
            for record, digest, details in rows]
