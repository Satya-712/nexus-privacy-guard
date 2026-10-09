
from src.privacy_detector import detect_sensitive_data


class ExposureTracker:
    def __init__(self):
        self.visible_exposures = []
        self.internal_traces = []

    def record_visible_output(self, channel, text):
        """Record sensitive data found in a visible channel."""

        findings = detect_sensitive_data(text)

        for finding in findings:
            self.visible_exposures.append({
                "channel": channel,
                "type": finding["type"],
                "value": finding["value"],
            })

        return findings

    def record_internal_trace(self, tool_name, text):
        """Keep internal tool traces separate from visible exposures."""

        findings = detect_sensitive_data(text)

        for finding in findings:
            self.internal_traces.append({
                "tool": tool_name,
                "type": finding["type"],
                "value": finding["value"],
            })

        return findings

    def get_summary(self):
        return {
            "visible_exposure_count": len(self.visible_exposures),
            "internal_trace_count": len(self.internal_traces),
            "visible_channels": sorted({
                item["channel"]
                for item in self.visible_exposures
            }),
        }
