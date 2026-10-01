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

from authlib.oauth2.base import OAuth2Error
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


def _base_claims():
    return {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "unique-jti",
    }


def _encode_token(key, claims=None, typ=None):
    base_claims = _base_claims()
    if claims:
        base_claims.update(claims)
    header = {"alg": "HS256"}
    if typ is not None:
        header["typ"] = typ
    return jwt.encode(header, base_claims, key)


def _validate_token(validator, token_string, scopes=None):
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


def test_valid_token_passes_full_validation():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, typ="at+jwt")
    token = _validate_token(validator, token_string)

    assert token["sub"] == "user-1"


def test_missing_typ_header_is_rejected():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    # a JWT without a "typ" header is accepted by authenticate_token but must
    # be rejected by the RFC 9068 validation step
    token = validator.authenticate_token(_encode_token(key))

    with pytest.raises(InvalidTokenError) as exc_info:
        validator.validate_token(token, None, None)

    assert exc_info.value.error == "invalid_token"
    assert exc_info.value.status_code == 401


@pytest.mark.parametrize("typ", ["jwt", "application/jwt", ""])
def test_invalid_typ_header_is_rejected(typ):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token = validator.authenticate_token(_encode_token(key, typ=typ))

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt", "AT+JWT"])
def test_allowed_typ_header_values(typ):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token = _validate_token(validator, _encode_token(key, typ=typ))

    assert token.header["typ"] == typ


@pytest.mark.parametrize(
    "missing_claim",
    ["iss", "exp", "aud", "iat", "jti", "client_id", "sub"],
)
def test_missing_required_claims_are_rejected(missing_claim):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    claims = _base_claims()
    del claims[missing_claim]
    token_string = jwt.encode({"alg": "HS256", "typ": "at+jwt"}, claims, key)

    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidTokenError) as exc_info:
        validator.validate_token(token, None, None)

    assert isinstance(exc_info.value, OAuth2Error)
    assert exc_info.value.error == "invalid_token"


def test_audience_list_containing_resource_server_is_accepted():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(
        key,
        claims={"aud": ["https://other.example.com", RESOURCE_SERVER]},
        typ="at+jwt",
    )
    token = _validate_token(validator, token_string)

    assert RESOURCE_SERVER in token["aud"]


def test_audience_list_without_resource_server_is_rejected():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(
        key,
        claims={"aud": ["https://other.example.com"]},
        typ="at+jwt",
    )
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


def test_expired_token_is_rejected():
    key = OctKey.generate_key()
    validator = _make_validator(key)
    now = int(time.time())

    token_string = _encode_token(
        key,
        claims={"iat": now - 7200, "exp": now - 3600},
        typ="at+jwt",
    )
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


def test_clock_skew_leeway_allows_recently_expired_token():
    key = OctKey.generate_key()
    validator = _make_validator(key)
    now = int(time.time())

    token_string = _encode_token(
        key,
        claims={"iat": now - 60, "exp": now - 30},
        typ="at+jwt",
    )
    token = validator.authenticate_token(token_string)

    token.validate(leeway=60)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


def test_clock_skew_leeway_allows_future_iat():
    key = OctKey.generate_key()
    validator = _make_validator(key)
    now = int(time.time())

    token_string = _encode_token(
        key,
        claims={"iat": now + 30, "exp": now + 3600},
        typ="at+jwt",
    )
    token = validator.authenticate_token(token_string)

    token.validate(leeway=60)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


def test_scope_string_is_accepted():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, claims={"scope": "profile email"}, typ="at+jwt")
    token = _validate_token(validator, token_string, scopes=["profile"])

    assert token["scope"] == "profile email"


def test_scope_list_is_accepted():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(
        key, claims={"scope": ["profile", "email"]}, typ="at+jwt"
    )
    token = _validate_token(validator, token_string, scopes=["email"])

    assert token["scope"] == ["profile", "email"]


@pytest.mark.parametrize("scope", [123, ["profile", 42], {"profile": True}])
def test_invalid_scope_claim_is_rejected(scope):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, claims={"scope": scope}, typ="at+jwt")
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


def test_insufficient_scope_raises_insufficient_scope_error():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(key, claims={"scope": "profile"}, typ="at+jwt")
    token = validator.authenticate_token(token_string)

    with pytest.raises(InsufficientScopeError) as exc_info:
        validator.validate_token(token, ["admin"], None)

    assert isinstance(exc_info.value, OAuth2Error)
    assert exc_info.value.error == "insufficient_scope"
    assert exc_info.value.status_code == 403


def test_authorization_details_are_accepted():
    key = OctKey.generate_key()
    validator = _make_validator(key)
    authorization_details = [
        {
            "type": "payment_initiation",
            "actions": ["initiate"],
            "amount": {"amount": "30.00", "currency": "EUR"},
        }
    ]

    token_string = _encode_token(
        key,
        claims={"authorization_details": authorization_details},
        typ="at+jwt",
    )
    token = _validate_token(validator, token_string)

    assert token["authorization_details"] == authorization_details
    assert "authorization_details" in token.get_registered_claims()


@pytest.mark.parametrize(
    "authorization_details",
    [
        "payment_initiation",
        {"type": "payment_initiation"},
        ["payment_initiation"],
        [{"actions": ["initiate"]}],
        [{"type": 42}],
        [{"type": ""}],
    ],
)
def test_invalid_authorization_details_are_rejected(authorization_details):
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token_string = _encode_token(
        key,
        claims={"authorization_details": authorization_details},
        typ="at+jwt",
    )
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)
