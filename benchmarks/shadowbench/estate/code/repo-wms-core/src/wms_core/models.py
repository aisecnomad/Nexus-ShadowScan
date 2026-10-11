"""ORM models for locations, pallets and pick orders."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Location(Base):
    __tablename__ = "locations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    aisle: Mapped[str] = mapped_column(String(8))
    rack: Mapped[str] = mapped_column(String(8))
    level: Mapped[int] = mapped_column(Integer)


class Pallet(Base):
    __tablename__ = "pallets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sscc: Mapped[str] = mapped_column(String(18), unique=True)
    location_id: Mapped[int | None] = mapped_column(ForeignKey("locations.id"))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class PickOrder(Base):
    __tablename__ = "pick_orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reference: Mapped[str] = mapped_column(String(24), unique=True)
    status: Mapped[str] = mapped_column(String(12), default="open")
    pallet_id: Mapped[int | None] = mapped_column(ForeignKey("pallets.id"))
