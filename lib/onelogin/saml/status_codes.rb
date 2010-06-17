module Onelogin::Saml
  module StatusCodes
    # See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 3.2.2 for further documentation
    SUCCESS_URI = "urn:oasis:names:tc:SAML:2.0:status:Success"
    REQUESTER_URI = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    RESPONDER_URI = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    VERSION_MISMATCH_URI = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
    AUTHN_FAILED_URI = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
    INVALID_ATTR_NAME_VALUE_URI = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
    INVALID_NAMEID_POLICY_URI = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
    NO_AUTHN_CONTEXT_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
    NO_AVAILABLE_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
    NO_PASSIVE_URI = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
    NO_SUPPORTED_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"
    PARTIAL_LOGOUT_URI = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
    PROXY_COUNT_EXCEEDED_URI = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"
    REQUEST_DENIED_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
    REQUEST_UNSUPPORTED_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
    REQUEST_VERSION_DEPRECATED_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
    REQUEST_VERSION_TOO_HIGH_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
    REQUEST_VERSION_TOO_LOW_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"
    RESOURCE_NOT_RECOGNIZED_URI = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
    TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"
    UNKNOWN_ATTR_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"
    UNKNOWN_PRINCIPAL_URI = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
    UNSUPPORTED_BINDING_URI = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
  end
end