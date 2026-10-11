"""Flask application factory."""

from flask import Flask

from wms_core.db import init_engine
from wms_core.routes import bp


def create_app(database_url: str) -> Flask:
    app = Flask(__name__)
    init_engine(database_url)
    app.register_blueprint(bp)
    return app
