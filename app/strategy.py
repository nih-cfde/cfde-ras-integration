from social_flask.strategy import FlaskStrategy
from flask import current_app


class RasStrategy(FlaskStrategy):
    current_app.config['REVOKE_TOKENS_ON_DISCONNECT'] = True
    current_app.config['DISCONNECT_REDIRECT_URL'] = \
        "https://authtest.nih.gov/siteminderagent/smlogoutredirector.asp?TARGET=https://ras-dev.nih-cfde.org"
    pass
