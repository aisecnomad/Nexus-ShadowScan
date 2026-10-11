-- Initial schema for the shed databases. Applied through alembic; kept in
-- plain SQL so the shed DBAs can review it.

CREATE TABLE locations (
    id     SERIAL PRIMARY KEY,
    aisle  VARCHAR(8)  NOT NULL,
    rack   VARCHAR(8)  NOT NULL,
    level  INTEGER     NOT NULL
);

CREATE TABLE pallets (
    id          SERIAL PRIMARY KEY,
    sscc        VARCHAR(18) NOT NULL UNIQUE,
    location_id INTEGER REFERENCES locations (id),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pick_orders (
    id        SERIAL PRIMARY KEY,
    reference VARCHAR(24) NOT NULL UNIQUE,
    status    VARCHAR(12) NOT NULL DEFAULT 'open',
    pallet_id INTEGER REFERENCES pallets (id)
);
