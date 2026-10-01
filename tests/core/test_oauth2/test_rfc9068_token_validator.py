"""Tests for RFC 9068 JWTBearerTokenValidator.authenticate_token.

Verifies that all joserfc errors raised during JWT decoding — including
InvalidKeyIdError — are converted to authlib's InvalidTokenError.
"""

import time

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

ISSUER = "https://auth.example.com"
RESOURCE_SERVER = "https://api.example.com"


def _make_validator(key):
    class Validator(JWTBearerTokenValidator):
        def get_jwks(self):
            return key

    return Validator(issuer=ISSUER, resource_server=RESOURCE_SERVER)


def _encode_token(key, claims=None, header=None):
    base_claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "unique-jti",
    }
    if claims:
        base_claims.update(claims)
    return jwt.encode(header or {"alg": "HS256"}, base_claims, key)


def _encode_rfc9068_token(key, claims=None):
    return _encode_token(key, claims, header={"alg": "HS256", "typ": "at+jwt"})


def _validate(validator, token_string, scopes=None):
    token = validator.authenticate_token(token_string)
    validator.validate_token(token, scopes, None)
    return token


def test_valid_token():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key)
    token = validator.authenticate_token(token_string)

    assert token is not None
    assert token["sub"] == "user-1"


def test_invalid_signature_raises_invalid_token_error():
    signing_key = OctKey.generate_key()
    wrong_key = OctKey.generate_key()
    validator = _make_validator(wrong_key)

    token_string = _encode_token(signing_key)

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_mismatched_kid_raises_invalid_token_error():
    """InvalidKeyIdError (not a subclass of DecodeError) must be caught."""
    key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-1"})
    key_set = KeySet(keys=[key])
    validator = _make_validator(key_set)

    # Encode a token with a kid that doesn't exist in the key set
    other_key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-999"})
    token_string = jwt.encode(
        {"alg": "RS256", "kid": "key-999"},
        {
            "iss": ISSUER,
            "aud": RESOURCE_SERVER,
            "sub": "user-1",
            "client_id": "client-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": "unique-jti",
        },
        other_key,
    )

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_garbage_token_raises_invalid_token_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token("not.a.jwt")


@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt"])
def test_valid_typ_header(typ):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, header={"alg": "HS256", "typ": typ})
    token = _validate(validator, token_string)
    assert token["sub"] == "user-1"


@pytest.mark.parametrize("typ", ["JWT", "jwt", "invalid"])
def test_invalid_typ_header_raises_invalid_token_error(typ):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, header={"alg": "HS256", "typ": typ})
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


@pytest.mark.parametrize("claim", ["iss", "exp", "aud", "iat", "jti", "client_id"])
def test_missing_required_claim_raises_invalid_token_error(claim):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(key, claims={claim: None})
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_missing_jti_raises_invalid_token_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token_string = jwt.encode({"alg": "HS256", "typ": "at+jwt"}, claims, key)
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_aud_as_list_containing_resource_server():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(
        key, claims={"aud": [RESOURCE_SERVER, "https://other.example.com"]}
    )
    token = _validate(validator, token_string)
    assert token["sub"] == "user-1"


def test_aud_as_list_without_resource_server_raises_invalid_token_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(
        key, claims={"aud": ["https://other.example.com"]}
    )
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_expired_token_raises_invalid_token_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(key, claims={"exp": int(time.time()) - 30})
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_clock_skew_leeway():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    # token expired 30 seconds ago: rejected without leeway, accepted with
    # enough leeway to account for clock skew
    token_string = _encode_rfc9068_token(key, claims={"exp": int(time.time()) - 30})
    token = validator.authenticate_token(token_string)
    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)
    token.validate(leeway=60)

    # token issued 30 seconds in the future: same leeway applies to 'iat'
    token_string = _encode_rfc9068_token(key, claims={"iat": int(time.time()) + 30})
    token = validator.authenticate_token(token_string)
    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)
    token.validate(leeway=60)


def test_scope_validation():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(key, claims={"scope": "profile email"})
    token = _validate(validator, token_string, scopes=["profile"])
    assert token["scope"] == "profile email"

    with pytest.raises(InsufficientScopeError):
        _validate(validator, token_string, scopes=["admin"])


def test_valid_authorization_details():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    authorization_details = [
        {
            "type": "payment_initiation",
            "actions": ["initiate"],
            "locations": ["https://api.example.com/payments"],
        }
    ]
    token_string = _encode_rfc9068_token(
        key, claims={"authorization_details": authorization_details}
    )
    token = _validate(validator, token_string)
    assert token["authorization_details"] == authorization_details


@pytest.mark.parametrize(
    "authorization_details",
    [
        "not-a-list",
        [{"actions": ["initiate"]}],
        [{"type": 42}],
        ["not-an-object"],
    ],
)
def test_invalid_authorization_details_raises_invalid_token_error(
    authorization_details,
):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_rfc9068_token(
        key, claims={"authorization_details": authorization_details}
    )
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)
