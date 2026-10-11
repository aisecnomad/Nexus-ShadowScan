from eta_graph.graph import review


def test_review_requires_shipment_id_in_draft() -> None:
    state = {"shipment_id": "VTR-88121", "draft": "VTR-88121 now 2026-10-12 14:00"}
    assert review(state)["approved"] is True
    assert review({"shipment_id": "VTR-88121"})["approved"] is False
