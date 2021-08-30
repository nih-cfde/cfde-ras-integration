from social_flask.strategy import FlaskStrategy
from flask import current_app


class RasStrategy(FlaskStrategy):
    current_app.config['REVOKE_TOKENS_ON_DISCONNECT'] = True
    pass
