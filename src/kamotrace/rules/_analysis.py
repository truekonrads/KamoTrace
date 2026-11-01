"""Shared robust window statistics and exact member linkage for offline analyses."""
from itertools import islice
import json
from statistics import median

MIN_REFERENCE_WINDOWS = 8
ROBUST_THRESHOLD = 6


def score_windows(counts, observed_windows, minimum, ratio):
    """Leave the scored window out; zeros exist only in otherwise observed windows."""
    signals, insufficient = [], 0
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
            signals.append((bucket, {
                "observed": observed, "reference_windows": reference_size,
                "reference_median": center, "reference_mad": mad,
                "robust_score": score, "fold_over_reference_floor_one": fold,
                "minimum_observed": minimum, "minimum_fold": ratio,
                "minimum_robust_score": ROBUST_THRESHOLD,
                "baseline_mode": "retrospective, other observed windows; scored window excluded"}))
    return signals, insufficient


def ordered_rows(connection, query, parameters=None):
    """Read ordered aggregates without retaining the whole result in Python."""
    connection.execute(query, parameters)
    while rows := connection.fetchmany(8192):
        yield from rows


def link_signals(connection, signals, rule_id, bucket_minutes):
    """Publish exact group/window members without materializing event matches in Python."""
    connection.execute("""CREATE TABLE analysis_signals(actor VARCHAR, bucket BIGINT,
        dimension VARCHAR, value VARCHAR, failures_only BOOLEAN, details JSON)""")
    # A separate connection can stage signals while the main connection streams its
    # temporary analysis tables. The staging table is removed before publication.
    count = 0
    signals = iter(signals)
    with connection.cursor() as writer:
        writer.begin()
        while batch := list(islice(signals, 8192)):
            rows = []
            for actor, bucket, dimension, value, failed, details in batch:
                details = {**details, "identity": json.loads(actor)}
                if "window_start_epoch" in details:
                    details["window_end_epoch"] = details["window_start_epoch"] + bucket_minutes * 60
                rows.append((actor, bucket, dimension, value, failed, json.dumps(details)))
            writer.executemany("INSERT INTO analysis_signals VALUES (?, ?, ?, ?, ?, ?)", rows)
            count += len(rows)
        writer.commit()
    connection.execute("""INSERT INTO matches
        SELECT e.source_record, e.record_sha256, ?, json_object(
            'signals', json_group_array(s.details),
            'link_basis', 'exact member of the scored recorded group/window; not proof of malicious activity',
            'bucket_minutes', ?, 'bucket_timezone', 'UTC')
        FROM analysis_events e JOIN analysis_signals s ON e.actor=s.actor
            AND (s.bucket IS NULL OR e.bucket=s.bucket)
            AND (NOT s.failures_only OR e.failed)
            AND CASE s.dimension WHEN 'operation' THEN e.operation=s.value
                WHEN 'asn' THEN e.asn=s.value WHEN 'country' THEN e.country=s.value ELSE true END
        GROUP BY e.source_record, e.record_sha256""", [rule_id, bucket_minutes])
    matches = connection.fetchone()[0]
    connection.execute("DROP TABLE analysis_signals")
    return matches, count
