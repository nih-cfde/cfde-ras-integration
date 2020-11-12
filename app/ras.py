from social_core.backends.open_id_connect import OpenIdConnectAuth


class RasOpenIDConnect(OpenIdConnectAuth):
    """
    RAS OAuth2 implementation in Python Social Auth
    Required Backend settings are as follows:
        SOCIAL_AUTH_RAS_KEY = '261c299a-1818-4177-a448-cb4f5602fe6d'
        SOCIAL_AUTH_RAS_SECRET = '4de57bc2-d15d-4290-98e9-91608ed02ab5'
    """

    name = 'ras'
    OIDC_ENDPOINT = 'https://stsstg.nih.gov'
    DEFAULT_JWKS_ALGORITHM = 'RS256'

    def get_remote_jwks_keys(self):
        keys = super().get_remote_jwks_keys()
        for key in keys:
            key['alg'] = key.get('alg', self.DEFAULT_JWKS_ALGORITHM)
        return keys
