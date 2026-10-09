
import json
from pathlib import Path

from src.privacy_detector import detect_sensitive_data


DATA_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "internal_visible_overlap.json"
)


def analyze_internal_visible_overlap():
    with DATA_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    sessions = {}

    for record in records:
        visibility = record["visibility"]

        if visibility not in {"internal", "visible"}:
            raise ValueError(
                f"Unsupported visibility: {visibility}"
            )

        findings = detect_sensitive_data(record["text"])

        session = sessions.setdefault(
            record["session_id"],
            {"internal": set(), "visible": set()},
        )

        for finding in findings:
            entity = (finding["type"], finding["value"])
            session[visibility].add(entity)

    results = []

    total_internal_entities = 0
    total_visible_entities = 0
    total_overlapping_entities = 0

    for session_id, data in sorted(sessions.items()):
        internal_entities = data["internal"]
        visible_entities = data["visible"]

        overlap = internal_entities & visible_entities

        total_internal_entities += len(internal_entities)
        total_visible_entities += len(visible_entities)
        total_overlapping_entities += len(overlap)

        results.append({
            "session_id": session_id,
            "internal_entity_count": len(internal_entities),
            "visible_entity_count": len(visible_entities),
            "overlap_count": len(overlap),
            "overlapping_entities": [
                {"type": kind, "value": value}
                for kind, value in sorted(overlap)
            ],
        })

    overlap_rate = (
        total_overlapping_entities / total_internal_entities
        if total_internal_entities else 0.0
    )

    return {
        "session_count": len(sessions),
        "internal_entity_count": total_internal_entities,
        "visible_entity_count": total_visible_entities,
        "overlap_count": total_overlapping_entities,
        "internal_to_visible_overlap_rate": overlap_rate,
        "details": results,
    }


if __name__ == "__main__":
    report = analyze_internal_visible_overlap()

    print("=== INTERNAL-TO-VISIBLE OVERLAP ===")
    print("Sessions:", report["session_count"])
    print("Unique internal entities:", report["internal_entity_count"])
    print("Unique visible entities:", report["visible_entity_count"])
    print("Overlapping entities:", report["overlap_count"])
    print(
        "Internal-to-visible overlap rate:",
        f"{report['internal_to_visible_overlap_rate']:.1%}",
    )

    print("\n=== SESSION DETAILS ===")
    for item in report["details"]:
        print(item)
