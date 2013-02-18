require 'zlib'
require "base64"
require "xml/libxml"
require "xml_sec"
require "cgi"

module Onelogin
  NAMESPACES = {
    "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
    "xenc" => "http://www.w3.org/2001/04/xmlenc#",
    "ds" => "http://www.w3.org/2000/09/xmldsig#"
  }

  # for SAML2 IDPs that omit the FriendlyName, map from the registered name
  # http://middleware.internet2.edu/dir/edu-schema-oid-registry.html
  ATTRIBUTES = {
    "urn:oid:1.3.6.1.4.1.5923.1.1.2" => "eduPerson",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" => "eduPersonAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7" => "eduPersonEntitlement",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.2" => "eduPersonNickname",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.3" => "eduPersonOrgDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.4" => "eduPersonOrgUnitDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.5" => "eduPersonPrimaryAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.8" => "eduPersonPrimaryOrgUnitDN",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" => "eduPersonPrincipalName",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.9" => "eduPersonScopedAffiliation",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" => "eduPersonTargetedID",
    "urn:oid:1.3.6.1.4.1.5923.1.2.2" => "eduOrg",
    "urn:oid:1.3.6.1.4.1.5923.1.2.1.2" => "eduOrgHomePageURI",
    "urn:oid:1.3.6.1.4.1.5923.1.2.1.3" => "eduOrgIdentityAuthNPolicyURI",
    "urn:oid:1.3.6.1.4.1.5923.1.2.1.4" => "eduOrgLegalName",
    "urn:oid:1.3.6.1.4.1.5923.1.2.1.5" => "eduOrgSuperiorURI",
    "urn:oid:1.3.6.1.4.1.5923.1.2.1.6" => "eduOrgWhitePagesURI",
  }
end

require 'onelogin/saml/auth_request'
require 'onelogin/saml/authn_contexts.rb'
require 'onelogin/saml/response'
require 'onelogin/saml/settings'
require 'onelogin/saml/name_identifiers'
require 'onelogin/saml/status_codes'
require 'onelogin/saml/meta_data'
require 'onelogin/saml/log_out_request'
require 'onelogin/saml/logout_response'
