# CFDE RAS Integration

This is a small webapp to demonstrate Auth in RAS. Users can both login to the
 portal to demonstrate RAS conforms to the OAuth2/OpenID spec, in addition to
 viewing extended passport information returned by RAS on successful login.
 
See [documentation on RAS here](https://authtest.nih.gov/iTrust/testOIDC.asp)
See the [deployment here](http://ras-dev.nih-cfde.org/)

### Portal Architecture

This portal is composed of three different components:

* Flask -- The webapp framework for handling requests
* [Python Social Auth](https://python-social-auth.readthedocs.io/en/latest/) -- A framework agnostic tool for handling the OAuth2 Flow
* [Bootstrap](https://getbootstrap.com/) -- For rendering templates

The `ras.py` auth module is a valid Python Social Auth Backend, and can be used
in any app which uses Python Social Auth. Configuration for the RAS auth module
looks like the following:

```
SOCIAL_AUTH_RAS_KEY = 'Your RAS client_id'
SOCIAL_AUTH_RAS_SECRET = 'Your RAS secret'
SOCIAL_AUTH_RAS_SCOPE = ['openid', 'profile', 'email', 'ga4gh_passport_v1']
```

### Development

Before starting, you'll need to request a client ID, client secret, and redirect URL
to configure your local portal. Redirect URLs for Python Social Auth typicall end with
`/complete/<provider>/`, examples for RAS are below:

```
http://localhost:5000/complete/ras/
https://ras-dev.nih-cfde.org/complete/ras/
``` 

1. Gather your RAS client ID and Secret, and place them in a file called `app/local_settings.py`
1. Run the following to setup your environment:
    * pipenv install
    * python manage.py syncdb
1. Run your local server:
    * python manage.py runserver
