"""Within-identity empirical rarity, not a probability of compromise."""
import math

from ._analysis import link_signals

ID = "kamotrace:conditional-rarity"
VERSION = 1
TITLE = "KamoTrace: Rare identity operation or network context"
LEVEL = "low"
TACTICS = []
TECHNIQUES = []
MIN_SUPPORT = 100
MAX_FREQUENCY = 0.01


def run(connection, context=None):
    dimensions, supported = connection.execute("""SELECT count(*),
        count(*) FILTER (WHERE events >= ? AND windows >= 8) FROM (
            SELECT actor, dimension, count(*) AS events, count(DISTINCT bucket) AS windows
            FROM analysis_dimensions WHERE dimension <> 'all' GROUP BY actor, dimension
        )""", [MIN_SUPPORT]).fetchone()
    rows = connection.execute("""WITH frequencies AS (
        SELECT actor, dimension, value, count(*) AS observed
        FROM analysis_dimensions WHERE dimension <> 'all' GROUP BY actor, dimension, value
    ), totals AS (
        SELECT *, sum(observed) OVER (PARTITION BY actor, dimension) AS total
        FROM frequencies
    ), support AS (
        SELECT actor, dimension, count(DISTINCT bucket) AS windows
        FROM analysis_dimensions GROUP BY actor, dimension
    ) SELECT actor, dimension, value, observed, total FROM totals JOIN support USING(actor, dimension)
        WHERE total >= ? AND windows >= 8 AND observed::DOUBLE / total <= ?
        ORDER BY actor, dimension, value""", [MIN_SUPPORT, MAX_FREQUENCY]).fetchall()
    signals = [(actor, None, dimension, value, False, {"dimension": dimension, "value": value,
        "observed": observed, "known_dimension_events": total, "frequency": observed / total,
        "rarity_bits": -math.log2(observed / total), "minimum_support": MIN_SUPPORT,
        "maximum_frequency": MAX_FREQUENCY,
        "baseline_mode": "retrospective within-identity empirical frequency in this dataset",
        "reason": f"{observed} of {total} recorded events with known {dimension} for this identity"})
        for actor, dimension, value, observed, total in rows]
    matches = link_signals(connection, signals)
    return matches, {"status": "completed", "matched_groups": len(signals), "matches": len(matches),
        "identity_dimensions": dimensions, "supported_identity_dimensions": supported,
        "minimum_support": MIN_SUPPORT, "maximum_frequency": MAX_FREQUENCY,
        "minimum_observed_windows": 8, "unknown_values": "excluded, not scored as rare"}
