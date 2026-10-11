"""HTTP routes for the receiving and picking desks."""

from flask import Blueprint, jsonify, request

from wms_core.db import session
from wms_core.models import Pallet, PickOrder

bp = Blueprint("wms", __name__)


@bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@bp.post("/pallets")
def receive_pallet():
    payload = request.get_json(force=True)
    with session() as db:
        pallet = Pallet(sscc=payload["sscc"])
        db.add(pallet)
        db.commit()
        return jsonify({"id": pallet.id}), 201


@bp.get("/pick-orders/<reference>")
def pick_order(reference: str):
    with session() as db:
        order = db.query(PickOrder).filter_by(reference=reference).one_or_none()
        if order is None:
            return jsonify({"detail": "not found"}), 404
        return jsonify({"reference": order.reference, "status": order.status})
