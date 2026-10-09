
def analyze_outlet_displacement(exposures, expected_channels):
    """
    Compare expected visible channels with actual exposure channels.

    exposures: list of visible exposure records.
    expected_channels: dictionary mapping data types to expected channels.
    """

    results = []

    for exposure in exposures:
        data_type = exposure["type"]
        actual_channel = exposure["channel"]

        expected_channel = expected_channels.get(data_type)

        if expected_channel is None:
            continue

        displaced = actual_channel != expected_channel

        results.append({
            "type": data_type,
            "expected_channel": expected_channel,
            "actual_channel": actual_channel,
            "displaced": displaced,
        })

    total = len(results)
    displaced_count = sum(
        item["displaced"] for item in results
    )

    return {
        "analyzed_exposures": total,
        "displaced_exposures": displaced_count,
        "displacement_rate": (
            displaced_count / total if total else 0.0
        ),
        "details": results,
    }
