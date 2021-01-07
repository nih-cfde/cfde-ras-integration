import json
from jose import jwk, jwt
from jose.jwt import JWTError, JWTClaimsError, ExpiredSignatureError
from jose.utils import base64url_decode
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError


class RasOpenIDConnect(OpenIdConnectAuth):
    """
    RAS OAuth2 implementation in Python Social Auth
    Required Backend settings are as follows:
        SOCIAL_AUTH_RAS_KEY = '261c299a-1818-4177-a448-cb4f5602fe6d'
        SOCIAL_AUTH_RAS_SECRET = '4de57bc2-d15d-4290-98e9-91608ed02ab5'
    """

    name = 'ras'
    USERINFO_URL = 'https://stsstg.nih.gov:443/openid/connect/v1.1/userinfo'
    OIDC_ENDPOINT = 'https://stsstg.nih.gov:443'
    EXTRA_DATA = [
        ('expires_in', 'expires_in', True),
        ('refresh_token', 'refresh_token', True),
        ('id_token', 'id_token', True),
        ('other_tokens', 'other_tokens', True),
        ('scope', 'scope', True),
        ('sub', 'sub', True),
        ('ga4gh_passport_v1', 'ga4gh_passport_v1', True),
    ]

    def get_user_details(self, response):
        # Only include passports that verify
        algorithm = self.get_algorithm(response['id_token'])
        passport_jwt = response.get('passport_jwt_v11')
        if passport_jwt:
            client_id, _ = self.get_key_and_secret()
            key = self.find_valid_key(passport_jwt)
            if not key:
                raise AuthTokenError(self, 'Signature verification failed')

            alg = key['alg']
            rsakey = jwk.construct(key)
            try:
                passport_envelope = jwt.decode(
                    passport_jwt,
                    rsakey.to_pem().decode('utf-8'),
                    algorithms=[algorithm],
                    audience=client_id,
                    issuer=self.id_token_issuer(),
                    access_token=response['access_token'],
                    options=self.JWT_DECODE_OPTIONS,
                )
                response['ga4gh_passport_v1'] = [
                    passport for passport in passport_envelope.get('ga4gh_passport_v1', [])
                    if self.verify_jwt(passport, algorithm)
                ]
            except ExpiredSignatureError:
                raise AuthTokenError(self, 'Signature has expired')
            except JWTClaimsError as error:
                raise AuthTokenError(self, str(error))
            except JWTError:
                raise AuthTokenError(self, 'Invalid signature')
        return super().get_user_details(response)

    def get_algorithm(self, id_token):
        """Get the algorithm 'alg' set on an id_token header"""
        header, _, _ = id_token.split('.')
        return json.loads(base64url_decode(header)).get('alg')

    def verify_jwt(self, jwt, algorithm):
        """Verifies a jwt and returns the key used to do so. Returns None if
        verification fails."""
        message, encoded_sig = jwt.rsplit('.', 1)
        decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))
        for key in self.get_jwks_keys():
            key['alg'] = key.get('alg') or algorithm
            rsakey = jwk.construct(key)
            if rsakey.verify(message.encode('utf-8'), decoded_sig):
                return key

    def find_valid_key(self, id_token):
        """
        Currently, 'alg' is not provided in the JWKS keys, which is needed by
        JOSE to determine the algorithm. This may be a bug, since the 'alg'
        field is optional for JWKS keys. The following looks for the 'alg' on
        the id_token if it is not provided in the JWKS keys.
        """
        return self.verify_jwt(id_token, self.get_algorithm(id_token))
