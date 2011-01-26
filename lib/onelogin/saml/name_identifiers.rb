module Onelogin::Saml
  module NameIdentifiers
    # See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for further documentation
    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    WINDOWS_DOMAIN = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
    X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
    
    ALL_IDENTIFIERS = [EMAIL, ENTITY, KERBEROS, PERSISTENT, TRANSIENT, UNSPECIFIED, WINDOWS_DOMAIN, X509]
  end
end