from joserfc.errors import InvalidClaimError
from joserfc.jwt import JWTClaimsRegistry

from authlib.oauth2.claims import JWTClaims


class JWTAccessTokenClaimsValidator(JWTClaimsRegistry):
    def validate_scope(self, scope):
        # The "scope" claim is defined in Section 4.2 of [RFC8693] as a JSON
        # string containing a space-separated list of scope values. A list of
        # strings is also accepted for interoperability.
        if isinstance(scope, str):
            scope_values = scope.split()
        elif isinstance(scope, (list, tuple)):
            scope_values = list(scope)
        else:
            raise InvalidClaimError("scope")

        for scope_value in scope_values:
            if not isinstance(scope_value, str) or not scope_value:
                raise InvalidClaimError("scope")

    def validate_authorization_details(self, authorization_details):
        # The "authorization_details" claim is defined in Section 2 of [RFC9396]
        # as a JSON array of objects, each containing a "type" field.
        if not isinstance(authorization_details, list):
            raise InvalidClaimError("authorization_details")

        for authorization_detail in authorization_details:
            if not isinstance(authorization_detail, dict):
                raise InvalidClaimError("authorization_details")
            detail_type = authorization_detail.get("type")
            if not isinstance(detail_type, str) or not detail_type:
                raise InvalidClaimError("authorization_details")

    def validate_auth_time(self, auth_time):
        if not isinstance(auth_time, (int, float)):
            raise InvalidClaimError("auth_time")
        self.check_value("auth_time", auth_time)

    def validate_amr(self, amr):
        if not isinstance(amr, list):
            raise InvalidClaimError("amr", amr)


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
        # Per Section 4 of [RFC9068], the resource server MUST verify that the
        # "typ" header value is "at+jwt" or "application/at+jwt" and reject
        # tokens carrying any other value (or carrying no value at all).
        if not isinstance(typ, str) or typ.lower() not in (
            "at+jwt",
            "application/at+jwt",
        ):
            raise InvalidClaimError("typ")
        super().validate(**kwargs)
