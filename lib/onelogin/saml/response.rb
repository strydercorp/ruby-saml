module Onelogin::Saml
  class Response
    
    attr_accessor :settings, :document, :xml, :response
    attr_accessor :name_id, :name_qualifier, :session_index
    attr_accessor :status_code, :status_message
    def initialize(response, settings)
      @response = response
      @settings = settings
      
      @xml = Base64.decode64(@response)
      @document = XMLSecurity::SignedDocument.new(@xml)
      @document.decrypt(@settings)
      
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