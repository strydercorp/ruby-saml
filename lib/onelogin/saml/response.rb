module Onelogin::Saml
  class Response
    attr_accessor :settings, :document, :response
    attr_accessor :name_id
    def initialize(response)
      @response = response
      @document = XMLSecurity::SignedDocument.new(Base64.decode64(@response))
      @name_id = @document.elements["/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"].text rescue nil
    end
    
    def logger=(val)
      @logger = val
    end
    
    def is_valid?
      unless @response.blank?
        @document.validate(@settings.idp_cert_fingerprint, @logger) unless !@settings.idp_cert_fingerprint
      end
    end
  end
end