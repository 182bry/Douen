from flask import Flask
from .config import Config
from .views.main import main_views
from .views.api import api_views
from .services.state import app_state


def create_app(overrides=None) -> Flask:
    app = Flask(__name__, static_url_path='/static')
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    app.register_blueprint(main_views)
    app.register_blueprint(api_views, url_prefix='/api')



    return app
