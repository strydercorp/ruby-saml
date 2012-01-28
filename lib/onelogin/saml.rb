require 'zlib'
require "base64"
require "rexml/document"
require "xml_sec"

module Onelogin
  NAMESPACES = {
    "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
    "xenc" => "http://www.w3.org/2001/04/xmlenc#",
    "ds" => "http://www.w3.org/2000/09/xmldsig#"
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