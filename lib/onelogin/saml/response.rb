module Onelogin::Saml
  class Response
    
    attr_reader :settings, :document, :xml, :response
    attr_reader :name_id, :name_qualifier, :session_index
    attr_reader :status_code, :status_message
    attr_reader :in_response_to, :destination
    attr_reader :validation_error
    def initialize(response, settings)
      @response = response
      @settings = settings
      
      @xml = Base64.decode64(@response)
      @document = XMLSecurity::SignedDocument.new(@xml)
      @document.decrypt(@settings)
      
      @in_response_to = REXML::XPath.first(@document, "/samlp:Response", Onelogin::NAMESPACES).attributes['InResponseTo'] rescue nil
      @destination = REXML::XPath.first(@document, "/samlp:Response", Onelogin::NAMESPACES).attributes['Destination'] rescue nil
      @name_id = REXML::XPath.first(@document, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", Onelogin::NAMESPACES).text rescue nil
      @name_qualifier = REXML::XPath.first(@document, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", Onelogin::NAMESPACES).attributes["NameQualifier"] rescue nil
      @session_index = REXML::XPath.first(@document, "/samlp:Response/saml:Assertion/saml:AuthnStatement", Onelogin::NAMESPACES).attributes["SessionIndex"] rescue nil
      @status_code = REXML::XPath.first(@document, "/samlp:Response/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES).attributes["Value"] rescue nil
      @status_message = REXML::XPath.first(@document, "/samlp:Response/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES).text rescue nil
    end
    
    def logger=(val)
      @logger = val
    end
    
    def is_valid?
      if !@response.blank? && @document.elements["//ds:X509Certificate"]
        if !@settings.idp_cert_fingerprint
          @validation_error = "No fingerprint configured in SAML settings"
          false
        elsif @document.validate(@settings.idp_cert_fingerprint, @logger)
          true
        else
          @validation_error = @document.validation_error
          false
        end
      elsif @response.blank?
        @validation_error = "No response to validate"
        false
      else
        @validation_error = "No ds:X509Certificate element"
        false
      end
    end
    
    def success_status?
      @status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end
    
    def auth_failure?
      @status_code == Onelogin::Saml::StatusCodes::AUTHN_FAILED_URI
    end
    
    def no_authn_context?
      @status_code == Onelogin::Saml::StatusCodes::NO_AUTHN_CONTEXT_URI
    end
    
    def fingerprint_from_idp
      if base64_cert = @document.elements["//ds:X509Certificate"]
        cert_text = Base64.decode64(base64_cert.text)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der)
      else
        nil
      end
    end
  end
end