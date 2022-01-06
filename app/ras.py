import json
import logging
import requests
from jose import jwk, jwt
from jose.jwt import JWTError, JWTClaimsError, ExpiredSignatureError
from jose.utils import base64url_decode
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError
from urllib.parse import urlencode
log = logging.getLogger(__name__)


class RasOpenIDConnect(OpenIdConnectAuth):
    """
    RAS OAuth2 implementation in Python Social Auth
    Set SOCIAL_AUTH_RAS_KEY and SOCIAL_AUTH_RAS_SECRET in local_settings.py
    """

    # Name should be 'ras' for production and 'globus' for local development
    name = 'ras'
    # name = 'globus'

    # Override the current v1 userinfo endpoint. The v1.1 endpoint returns
    # userinfo in a JWT token instead of plain JSON. If not specified,
    # /userinfo will default to the value in .well-known/openid-configuration
    OIDC_ENDPOINT = 'https://stsstg.nih.gov'
    USERINFO_URL = f"{OIDC_ENDPOINT}/openid/connect/v1.1/userinfo"
    REVOKE_TOKEN_URL = f"{OIDC_ENDPOINT}/auth/oauth/v2/token/revoke"
    REVOKE_TOKEN_METHOD = 'POST'
    LOGOUT_URL = f"{OIDC_ENDPOINT}/connect/session/logout"

    # The 'ga4gh_passport_v1' json object will be returned within /userinfo
    # if the ga4gh_passport_v1 scope is present.
    PASSPORT = 'ga4gh_passport_v1'

    # If using v1.1, the `ga4gh_passport_v1' will be nested within an
    # additional JWT called 'passport_jwt_v11'.
    PASSPORT_JWT_ENVELOPE = 'passport_jwt_v11'
    GET_ALL_EXTRA_DATA = True
    USERINFO = dict()

    def user_data(self, access_token, *args, **kwargs):
        """Fetch userinfo data. RAS returns an empty json response for v1.1 if
        the scopes are ['openid', 'profile', 'email']"""
        try:
            self.USERINFO = self.get_json(self.userinfo_url(),
                                     headers={'Authorization': 'Bearer {0}'.format(access_token)})
            return self.USERINFO
        except json.decoder.JSONDecodeError:
            # This happens if the 'ga4gh_passport_v1' scope is not requested
            # on version 1.1. I'm pretty sure this is a bug in RAS.
            log.error(f'Endpoint {self.userinfo_url()} did not return JSON!')
            return {}

    def get_user_details(self, response):
        # Only include passports that verify
        response[self.PASSPORT] = self.get_ga4gh_passport(response)
        response['userinfo'] = self.USERINFO
        return super().get_user_details(response)

    def get_ga4gh_passport(self, response):
        """Fetch the 'ga4gh_passport_v1 included within information returned
        by /userinfo. Works for both v1 and v1.1 versions on RAS."""
        algorithm = self.get_algorithm(response['id_token'])
        if response.get(self.PASSPORT_JWT_ENVELOPE):
            # The ga4gh passport will be concealed within an additional JWT
            # Envelope. Verify both the JWT envelope AND the (list of) JWT
            # passports.
            log.info(f'Loading Passport with /userinfo endpoint v1.1')
            passport_jwt = response[self.PASSPORT_JWT_ENVELOPE]
            client_id, _ = self.get_key_and_secret()
            key = self.find_valid_key(passport_jwt)
            if not key:
                raise AuthTokenError(self, 'Signature verification failed '
                                           'on Passport JWT')
            try:
                passport_envelope = jwt.decode(
                    passport_jwt,
                    jwk.construct(key).to_pem().decode('utf-8'),
                    algorithms=[algorithm],
                    audience=client_id,
                    issuer=self.OIDC_ENDPOINT,
                    access_token=response['access_token'],
                    options=self.JWT_DECODE_OPTIONS,
                )
                passport = passport_envelope[self.PASSPORT]
                return self.verify_passport(passport, algorithm)
            except (ExpiredSignatureError, JWTClaimsError, JWTError) as e:
                raise AuthTokenError(self,
                                     f'RAS GA4GH token validation error: {e}')
        elif response.get(self.PASSPORT):
            # The /userinfo v1 endpoint does NOT wrap the ga4gh passport in a
            # JWT. Simply verify the passport and return it.
            log.info(f'Loading Passport with /userinfo endpoint v1')
            return self.verify_passport(response[self.PASSPORT], algorithm)

    def verify_passport(self, ga4gh_passport_v1, algorithm):
        """Verify a ga4gh_passport_v1. These are a list of JWT tokens. Each
        one should pass validation"""
        return [
            passport for passport in ga4gh_passport_v1
            if self.verify_jwt(passport, algorithm)
        ]

    def get_algorithm(self, jwt_token):
        """Get the algorithm 'alg' set on a JWT token header"""
        header, _, _ = jwt_token.split('.')
        return json.loads(base64url_decode(header + '=')).get('alg')

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

    def revoke_token_params(self, token, uid):
        key, secret = self.get_key_and_secret()
        params = {"client_id": key,
                  "client_secret": secret,
                  "id_token": self.id_token,
                  "token_type_hint": "access_token",
                  "token": token,
                  }
        return params

    def revoke_token_headers(self, token, uid):
        header = {'Content-type': 'application/x-www-form-urlencoded'}
        return header

    def revoke_token(self, token, uid):
        params = self.revoke_token_params(token, uid)
        headers = self.revoke_token_headers(token, uid)
        url = self.revoke_token_url(token, uid)
        if self.REVOKE_TOKEN_METHOD == 'GET':
            data = None
        else:
            data = urlencode(params)
        response = requests.post(url=url, headers=headers, data=data)
        self.logout(token, uid)
        return self.process_revoke_token_response(response)

    def logout(self, token, uid):
        key, secret = self.get_key_and_secret()
        params = {"client_id": key,
                  "client_secret": secret,
                  "id_token": self.id_token}
        headers = self.revoke_token_headers(token, uid)
        data = urlencode(params)
        requests.post(self.LOGOUT_URL, headers=headers, data=data)
        return True
