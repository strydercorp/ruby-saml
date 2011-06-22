module Onelogin::Saml
  class Response
    
    attr_accessor :settings, :document, :response
    attr_accessor :name_id, :name_qualifier, :session_index
    attr_accessor :status_code, :status_message
    def initialize(response)
      @response = response
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(@response))
      @name_id = @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text rescue nil
      @name_qualifier = @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].attributes["NameQualifier"] rescue nil
      @session_index = @document.elements["/samlp:Response/saml:Assertion/saml:AuthnStatement"].attributes["SessionIndex"] rescue nil
      @status_code = @document.elements["/samlp:Response/samlp:Status/samlp:StatusCode"].attributes["Value"] rescue nil
      @status_message = @document.elements["/samlp:Response/samlp:Status/samlp:StatusCode"].text rescue nil
      # look for saml2 and saml2p tags in Shibboleth assertions
      @name_id ||= @document.elements["/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID"].text rescue nil
      @name_qualifier ||= @document.elements["/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID"].attributes["NameQualifier"] rescue nil
      @session_index ||= @document.elements["/saml2p:Response/saml2:Assertion/saml2:AuthnStatement"].attributes["SessionIndex"] rescue nil
      @status_code ||= @document.elements["/saml2p:Response/saml2p:Status/saml2p:StatusCode"].attributes["Value"] rescue nil
      @status_message ||= @document.elements["/saml2p:Response/saml2p:Status/saml2p:StatusCode"].text rescue nil     
    end
    
    def logger=(val)
      @logger = val
    end
    
    def is_valid?
      unless @response.blank?
        @document.validate(@settings.idp_cert_fingerprint, @logger) unless !@settings.idp_cert_fingerprint
      end
    end
    
    def success_status?
      @status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end
    
    def auth_failure?
      @status_code == Onelogin::Saml::StatusCodes::AUTHN_FAILED_URI
    end
  end
end