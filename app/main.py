import jose
import json
import logging.config
import os
import requests

from flask import Flask, g
from flask_login import LoginManager, current_user

from social_core.backends.utils import load_backends
from social_flask.utils import load_strategy
from social_flask.routes import social_auth
from social_flask.template_filters import backends
from social_flask_sqlalchemy.models import init_social

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from app.ras import RasOpenIDConnect


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# App
app = Flask(
    'RAS Example App',
    template_folder=os.path.join(BASE_DIR, 'app', 'templates')
)
app.config.from_object('app.settings')

try:
    app.config.from_object('app.local_settings')
except ImportError:
    pass

logging.config.dictConfig(app.config['LOGGING_DICT_CONFIG'])
log = logging.getLogger(__name__)
log.debug('Debug logging enabled')

# DB
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db_session = scoped_session(Session)

app.register_blueprint(social_auth)
init_social(app, db_session)

login_manager = LoginManager()
login_manager.login_view = 'main'
login_manager.login_message = ''
login_manager.init_app(app)

from app import models  # noqa
from app import views  # noqa


@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.query.get(int(userid))
    except (TypeError, ValueError):
        pass


@app.before_request
def global_user():
    # evaluate proxy value
    g.user = current_user._get_current_object()


@app.teardown_appcontext
def commit_on_success(error=None):
    if error is None:
        db_session.commit()
    else:
        db_session.rollback()

    db_session.remove()


@app.context_processor
def auth_context():
    """Common view context"""
    authentication_backends = app.config['SOCIAL_AUTH_AUTHENTICATION_BACKENDS']
    user = getattr(g, 'user', None)
    strategy = load_strategy()

    context = {
        'user': user,
        'available_backends': load_backends(authentication_backends),
        'associated': {}
    }

    if user and user.is_authenticated:
        context['associated'] = {
            assoc.provider: assoc
            for assoc in strategy.storage.user.get_social_auth_for_user(user)
        }
    return context


def social_url_for(name, **kwargs):
    login_urls = {
        'social:begin': '/login/{backend}/',
        'social:complete': '/complete/{backend}/',
        'social:disconnect': '/disconnect/{backend}/',
        'social:disconnect_individual': '/disconnect/{backend}/{association_id}/',
    }
    return login_urls.get(name, name).format(**kwargs)


def get_jwt_payload(jwt_obj):
    """Fetches payload information for a given jwt object. Does not attempt to
    verify any signatures on the JWT, only returns the payload dict."""
    return json.loads(jose.jws.verify(jwt_obj, None, [], verify=False))


def get_userinfo_version():
    url = RasOpenIDConnect.USERINFO_URL
    if not url:
        # This is easier than instantiating RasOpenIDConnect() to fetch the
        # OIDC config for us.
        oidc_cfg = 'https://stsstg.nih.gov/.well-known/openid-configuration'
        url = requests.get(oidc_cfg).json()['userinfo_endpoint']
    version = url.replace('https://stsstg.nih.gov/openid/connect/', '')
    return version.replace('/userinfo', '')


@app.template_filter('pretty_json')
def pretty_json(j):
    return json.dumps(j, indent=4)


app.context_processor(backends)
app.jinja_env.globals['url'] = social_url_for
app.jinja_env.globals['get_jwt_payload'] = get_jwt_payload
app.jinja_env.globals['get_userinfo_version'] = get_userinfo_version
