from os.path import dirname, abspath, join

SECRET_KEY = 'random-secret-key'
SESSION_COOKIE_NAME = 'psa_session'
DEBUG = True
SQLALCHEMY_DATABASE_URI = 'sqlite:////%s/db.sqlite3' % dirname(
    abspath(join(__file__, '..'))
)
DEBUG_TB_INTERCEPT_REDIRECTS = False
SESSION_PROTECTION = 'strong'

SOCIAL_AUTH_LOGIN_URL = '/'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
SOCIAL_AUTH_USER_MODEL = 'app.models.User'
SOCIAL_AUTH_STORAGE = 'social_flask_sqlalchemy.models.FlaskStorage'
SOCIAL_AUTH_STRATEGY = 'app.strategy.RasStrategy'
SOCIAL_AUTH_AUTHENTICATION_BACKENDS = (
    # 'social_core.backends.globus.GlobusOpenIdConnect',
    'app.ras.RasOpenIDConnect',
)

LOGGING_DICT_CONFIG = {
    'version': 1,
    'formatters': {
        'basic': {'format': '[%(levelname)s] '
                            '%(name)s::%(funcName)s() %(message)s'}
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'WARNING',
            'formatter': 'basic',
        }
    },
    'loggers': {
        'app': {'level': 'DEBUG', 'handlers': ['console']},
    },
}
