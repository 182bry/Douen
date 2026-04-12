from flask import Flask, redirect, url_for
from .config import Config
from .database import db, init_db
from .views.main import main_views
from .views.api import api_views
from .views.auth import auth_views
from .controllers.auth import setup_jwt, add_auth_context
from .services.state import app_state


def create_app(overrides=None) -> Flask:
    app = Flask(__name__, static_url_path='/static')
    app.config.from_object(Config)

    
    app.config['JWT_SECRET_KEY'] = app.config.get('SECRET_KEY', 'dev-secret-key')

    
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///douen.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if overrides:
        app.config.update(overrides)

    
    init_db(app)

    
    setup_jwt(app)

    
    add_auth_context(app)

    
    app.register_blueprint(main_views)
    app.register_blueprint(api_views, url_prefix='/api')
    app.register_blueprint(auth_views, url_prefix='/auth')

    
    with app.app_context():
        db.create_all()

    return app
'''
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
'''