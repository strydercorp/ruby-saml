module Onelogin::Saml
  module AuthnContexts
    # see section 3.4 of http://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf
    INTERNET_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
    INTERNET_PROTOCOL_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
    KERBEROS = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
    MOBILE_ONE_FACTOR_UNREGISTERED = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
    MOBILE_TWO_FACTOR_UNREGISTERED = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
    MOBILE_ONE_FACTOR_CONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
    MOBILE_TWO_FACTOR_CONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
    PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
    PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    PREVIOUS_SESSION = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
    X509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
    PGP = "urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
    SPKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
    XMLD_SIG = "urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"
    SMARTCARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
    SOFTWARE_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
    TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
    NOMAD_TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
    PERSONAL_TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"
    AUTHENTICATED_TELEPHONY = "urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
    SECURE_REMOTE_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
    TLS_CLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
    TIME_SYNC_TOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
    UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
    
    ALL_CONTEXTS = [INTERNET_PROTOCOL_PASSWORD, KERBEROS, MOBILE_ONE_FACTOR_UNREGISTERED,
                    MOBILE_TWO_FACTOR_UNREGISTERED, MOBILE_ONE_FACTOR_CONTRACT, MOBILE_TWO_FACTOR_CONTRACT,
                    PASSWORD, PASSWORD_PROTECTED_TRANSPORT, PREVIOUS_SESSION, X509, PGP, SPKI, XMLD_SIG,
                    SMARTCARD_PKI, SOFTWARE_PKI, TELEPHONY, NOMAD_TELEPHONY, PERSONAL_TELEPHONY,
                    AUTHENTICATED_TELEPHONY, SECURE_REMOTE_PASSWORD, TLS_CLIENT, TIME_SYNC_TOKEN, UNSPECIFIED]
  end
end