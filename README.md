# AI Agent Privacy Guard

Research prototype for detecting, analyzing, and redacting sensitive data in AI-agent session outputs.

## Overview

AI Agent Privacy Guard is a Python project that demonstrates:
- Sensitive-data detection using regular expressions
- Expected-channel versus all-visible-channel comparison
- Synthetic authorization-label auditing
- Internal-to-visible entity overlap analysis
- Sensitive-data redaction
- Interactive Streamlit dashboard
- Automated unit testing

## Technologies

- Python
- Streamlit
- Pandas
- JSON
- Regular expressions
- unittest

## Project Structure

```text
ai-agent-privacy-guard/
|-- dashboard.py
|-- main.py
|-- README.md
|-- data/
|   |-- experiments.json
|   |-- internal_visible_overlap.json
|-- src/
|   |-- authorization_checker.py
|   |-- displacement_analyzer.py
|   |-- evaluation_pipeline.py
|   |-- exposure_tracker.py
|   |-- internal_visible_overlap.py
|   |-- outlet_comparison.py
|   |-- outlet_comparison_data.py
|   |-- privacy_detector.py
|   |-- privacy_redactor.py
|   |-- run_experiment.py
|-- tests/
    |-- test_evaluation_pipeline.py
    |-- test_privacy_detector.py
    |-- test_privacy_redactor.py
```

## Installation

Install the required packages:

```powershell
python -m pip install streamlit pandas
```

## Run the Dashboard

From the project root:

```powershell
python -m streamlit run dashboard.py
```

Open the local URL shown in the terminal, usually `http://localhost:8501`.

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

Latest recorded test result: 12 tests passed.

## Synthetic Experiment Results

### Detector evaluation

| Metric | Result |
|---|---:|
| Test records | 5 |
| Accuracy | 100.0% |
| Precision | 100.0% |
| Recall | 100.0% |

### Outlet displacement comparison

| Measure | Result |
|---|---:|
| Visible sensitive records considered | 3 |
| Expected-only recovery | 2 of 3 (66.7%) |
| All-visible-channel recovery | 3 of 3 (100.0%) |
| Missed by expected-only | 1 |
| Displacement rate | 33.3% |

### Internal-to-visible overlap

| Measure | Result |
|---|---:|
| Sessions | 4 |
| Internal entities counted across sessions | 4 |
| Visible entities counted across sessions | 3 |
| Overlapping entities | 2 |
| Overlap rate | 50.0% |

## Limitations

- The datasets are small and synthetic.
- Detection supports only a limited set of patterns.
- False positives and false negatives may occur on other text formats.
- Exact matching may miss alternate representations or transformed values.
- Visibility and authorization labels are supplied by the synthetic datasets.
- The prototype does not guarantee complete privacy protection.

The displayed metrics describe only the current synthetic examples. They are not real-world performance estimates and are not reproduced results from the original research paper.

## Future Improvements

- Expand the synthetic evaluation dataset.
- Add edge-case and robustness tests.
- Improve detection coverage.
- Strengthen redaction and sensitive-value handling.
- Evaluate with a larger, carefully labeled benchmark.
- Add reproducible experiment exports.

## Conclusion

AI Agent Privacy Guard demonstrates a modular workflow for sensitive-data detection, outlet displacement comparison, synthetic authorization auditing, internal-to-visible overlap analysis, and redaction.

The prototype currently includes a Streamlit dashboard and a suite of 12 passing unit tests. Broader performance claims require more extensive evaluation.

**Project type:** Research prototype  
**Dataset:** Synthetic experiments
