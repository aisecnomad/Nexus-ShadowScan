# wms-core

Warehouse management core service for Adatum Logistics: receiving,
locations and pick orders for the Katowice and Rotterdam sheds.

Internal clone: `git@git.adatum.example:platform/repo-wms-core.git`

## Run

    pip install -e .
    gunicorn "wms_core.app:create_app('postgresql://wms@localhost/wms')"

Schema changes go through `migrations/` and alembic; never edit tables by
hand on the shed databases.
