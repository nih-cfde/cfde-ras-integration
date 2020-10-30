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
SOCIAL_AUTH_AUTHENTICATION_BACKENDS = (
    'social_core.backends.globus.GlobusOpenIdConnect',
    # 'social_core.backends.github.GithubOAuth2',
    # 'social_core.backends.google.GoogleOAuth2',
    # 'social_core.backends.google.GoogleOpenId',
    # 'social_core.backends.slack.SlackOAuth2'
)
