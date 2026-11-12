import pytest
from security_eval.scoring import evaluate


def test_scoring_tp_fp_fn():
    actual = evaluate([{"case_id": "a", "cwe": "CWE-22"}, {"case_id": "b", "cwe": "CWE-79"}],
                      [{"case_id": "a", "cwe": "CWE-22"}, {"case_id": "c", "cwe": "CWE-89"}])
    assert actual == {"true_positives": 1, "false_positives": 1, "false_negatives": 1,
                      "precision": 0.5, "recall": 0.5, "f1": 0.5}


def test_empty_inputs():
    assert evaluate([], [])["f1"] == 0.0


def test_duplicates_do_not_inflate_score():
    item = {"case_id": "a", "cwe": "CWE-22"}
    assert evaluate([item], [item, item])["true_positives"] == 1


def test_invalid_cwe_rejected():
    with pytest.raises(ValueError):
        evaluate([], [{"case_id": "a", "cwe": "INVALID"}])
