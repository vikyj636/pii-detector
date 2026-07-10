"""NER detector unit tests. The GLiNER2 model is always mocked — these tests
must run without torch/gliner2 installed."""
from __future__ import annotations

from app.config import resolve_thresholds
from app.detectors.ner_detector import NERDetector, chunk_text, normalize_ner_output


class ShapeModel:
    """Returns a fixed raw payload, accepting any call signature."""

    def __init__(self, raw):
        self.raw = raw

    def extract_entities(self, text, labels, **kwargs):
        return self.raw


def detect(raw, text, labels, thresholds=None, window=1500, overlap=200):
    detector = NERDetector(ShapeModel(raw), window, overlap)
    return detector.detect(text, labels, resolve_thresholds(thresholds))


def test_grouped_dict_with_scores():
    text = "Mario Rossi lives in Milano"
    raw = {"entities": {"person": [{"text": "Mario Rossi", "start": 0, "end": 11, "score": 0.82}]}}
    entities = detect(raw, text, ["person"])
    assert len(entities) == 1
    e = entities[0]
    assert (e.start, e.end, e.type, e.source) == (0, 11, "person", "ner")
    assert abs(e.confidence - 0.82) < 1e-6
    assert text[e.start : e.end] == e.text == "Mario Rossi"


def test_grouped_strings_locates_every_occurrence():
    text = "Anna met Anna"
    entities = detect({"person": ["Anna"]}, text, ["person"], thresholds={"person": 0.5})
    assert sorted((e.start, e.end) for e in entities) == [(0, 4), (9, 13)]
    # String-only output carries no scores: confidence degrades to the applied
    # minimum threshold (the model's own filtering is the only gate).
    assert all(e.confidence == 0.5 for e in entities)


def test_flat_list_shape():
    text = "Mario Rossi"
    raw = [{"text": "Mario Rossi", "label": "person", "start": 0, "end": 11, "score": 0.9}]
    entities = detect(raw, text, ["person"])
    assert len(entities) == 1 and entities[0].confidence == 0.9


def test_below_default_threshold_dropped():
    raw = {"entities": {"person": [{"text": "Mario", "start": 0, "end": 5, "score": 0.6}]}}
    assert detect(raw, "Mario", ["person"]) == []  # person default threshold is 0.7


def test_per_request_threshold_override():
    raw = {"entities": {"person": [{"text": "Mario", "start": 0, "end": 5, "score": 0.6}]}}
    entities = detect(raw, "Mario", ["person"], thresholds={"person": 0.55})
    assert len(entities) == 1


def test_unrequested_labels_dropped():
    raw = {"entities": {"organization": [{"text": "ACME", "start": 0, "end": 4, "score": 0.9}]}}
    assert detect(raw, "ACME corp", ["person"]) == []


def test_call_signature_fallback():
    class OldSignatureModel:
        def extract_entities(self, text, labels):  # no threshold/include_confidence kwargs
            return {"person": [{"text": "Mario", "start": 0, "end": 5, "score": 0.99}]}

    detector = NERDetector(OldSignatureModel())
    entities = detector.detect("Mario", ["person"], resolve_thresholds(None))
    assert len(entities) == 1


def test_chunking_offsets_and_dedupe():
    class FindingModel:
        """Finds 'Mario Rossi' in whatever chunk it is given."""

        def extract_entities(self, chunk, labels, **kwargs):
            out, idx = [], chunk.find("Mario Rossi")
            while idx != -1:
                out.append(
                    {"text": "Mario Rossi", "label": "person", "start": idx, "end": idx + 11, "score": 0.9}
                )
                idx = chunk.find("Mario Rossi", idx + 1)
            return out

    text = ("lorem ipsum " * 140)[:1600] + "Mario Rossi" + " tail" * 60
    detector = NERDetector(FindingModel(), window_chars=800, overlap_chars=100)
    entities = detector.detect(text, ["person"], resolve_thresholds(None))
    assert len(entities) == 1  # overlap duplicates collapse to one global span
    e = entities[0]
    assert text[e.start : e.end] == "Mario Rossi"


def test_chunk_text_covers_all_characters():
    text = ("word " * 400).strip()
    chunks = chunk_text(text, 300, 50)
    assert len(chunks) > 1
    covered: set[int] = set()
    for offset, chunk in chunks:
        assert text[offset : offset + len(chunk)] == chunk
        covered.update(range(offset, offset + len(chunk)))
    assert covered == set(range(len(text)))


def test_normalize_handles_unknown_shape():
    assert normalize_ner_output(42, "text", {"person"}) == []
    assert normalize_ner_output(None, "text", {"person"}) == []


def test_empty_inputs():
    detector = NERDetector(ShapeModel({}))
    assert detector.detect("", ["person"], resolve_thresholds(None)) == []
    assert detector.detect("text", [], resolve_thresholds(None)) == []
