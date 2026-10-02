from flask import Flask
from .db import init_db
from .routes import bp


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY="change-me-in-production",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        DATABASE="phishscope.db",
    )

    app.register_blueprint(bp)

    with app.app_context():
        init_db()

    return app
