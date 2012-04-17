module Onelogin::Saml
  class Response
    
    attr_reader :settings, :document, :decrypted_document, :xml, :response
    attr_reader :name_id, :name_qualifier, :session_index
    attr_reader :status_code, :status_message
    attr_reader :in_response_to, :destination
    attr_reader :validation_error
    def initialize(response, settings)
      @response = response
      @settings = settings
      
      @xml = Base64.decode64(@response)
      @document = LibXML::XML::Document.string(@xml)
      @document.extend(XMLSecurity::SignedDocument)
      
      @decrypted_document = LibXML::XML::Document.document(@document)
      @decrypted_document.extend(XMLSecurity::SignedDocument)
      @decrypted_document.decrypt(@settings)
      
      @in_response_to = @decrypted_document.find_first("/samlp:Response", Onelogin::NAMESPACES)['InResponseTo'] rescue nil
      @destination = @decrypted_document.find_first("/samlp:Response", Onelogin::NAMESPACES)['Destination'] rescue nil
      @name_id = @decrypted_document.find_first("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", Onelogin::NAMESPACES).content rescue nil
      @name_qualifier = @decrypted_document.find_first("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", Onelogin::NAMESPACES)["NameQualifier"] rescue nil
      @session_index = @decrypted_document.find_first("/samlp:Response/saml:Assertion/saml:AuthnStatement", Onelogin::NAMESPACES)["SessionIndex"] rescue nil
      @status_code = @decrypted_document.find_first("/samlp:Response/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES)["Value"] rescue nil
      @status_message = @decrypted_document.find_first("/samlp:Response/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES).content rescue nil
    end
    
    def logger=(val)
      @logger = val
    end
    
    def is_valid?
      if @response.nil? || @response == ""
        @validation_error = "No response to validate"
        return false
      end
      
      if @document.find_first("//ds:X509Certificate", Onelogin::NAMESPACES).nil?
        @validation_error = "No ds:X509Certificate element"
        return false
      end
      
      if !@settings.idp_cert_fingerprint
        @validation_error = "No fingerprint configured in SAML settings"
        return false
      end
      
      if !@document.validate(@settings.idp_cert_fingerprint, @logger)
        @validation_error = @document.validation_error
        return false
      end
      
      true
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
      if base64_cert = @document.find_first("//ds:X509Certificate")
        cert_text = Base64.decode64(base64_cert.content)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der)
      else
        nil
      end
    end
  end
end