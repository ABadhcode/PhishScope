from flask import Flask
from .db import init_db

def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    init_db()
    from .routes import bp
    app.register_blueprint(bp)
    return app
