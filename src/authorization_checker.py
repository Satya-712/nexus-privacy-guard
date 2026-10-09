
def check_authorization(data_type, authorized_types):
    """
    Check whether a data type is explicitly authorized
    for the simulated task.
    """

    is_authorized = data_type in authorized_types

    return {
        "type": data_type,
        "authorized": is_authorized,
        "status": "AUTHORIZED" if is_authorized else "UNAUTHORIZED",
    }


def audit_exposures(exposures, authorized_types):
    """
    Audit visible exposures against the authorization policy.
    """

    results = []

    for exposure in exposures:
        result = check_authorization(
            exposure["type"],
            authorized_types,
        )

        results.append({
            "channel": exposure["channel"],
            "type": exposure["type"],
            "authorized": result["authorized"],
            "status": result["status"],
        })

    return results
