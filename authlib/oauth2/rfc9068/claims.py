from joserfc.errors import InvalidClaimError
from joserfc.jwt import JWTClaimsRegistry

from authlib.oauth2.claims import JWTClaims


class JWTAccessTokenClaimsValidator(JWTClaimsRegistry):
    def validate_auth_time(self, auth_time):
        if not isinstance(auth_time, (int, float)):
            raise InvalidClaimError("auth_time")
        self.check_value("auth_time", auth_time)

    def validate_amr(self, amr):
        if not isinstance(amr, list):
            raise InvalidClaimError("amr", amr)

    def validate_authorization_details(self, authorization_details):
        # The 'authorization_details' claim, as defined by RFC9396, is an array
        # of JSON objects. Each object MUST contain a 'type' field whose value
        # is a string.
        if not isinstance(authorization_details, list):
            raise InvalidClaimError("authorization_details")
        for details in authorization_details:
            if not isinstance(details, dict) or not isinstance(
                details.get("type"), str
            ):
                raise InvalidClaimError("authorization_details")
        self.check_value("authorization_details", authorization_details)


class JWTAccessTokenClaims(JWTClaims):
    registry_cls = JWTAccessTokenClaimsValidator
    REGISTERED_CLAIMS = JWTClaims.REGISTERED_CLAIMS + [
        "client_id",
        "auth_time",
        "acr",
        "amr",
        "scope",
        "authorization_details",
        "groups",
        "roles",
        "entitlements",
    ]

    def validate(self, **kwargs):
        typ = self.header.get("typ")
        if typ and typ.lower() not in ("at+jwt", "application/at+jwt"):
            raise InvalidClaimError("typ")
        super().validate(**kwargs)
