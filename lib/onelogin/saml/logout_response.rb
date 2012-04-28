module Onelogin::Saml
  class LogoutResponse
    
    attr_reader :settings, :document, :xml, :response
    attr_reader :status_code, :status_message
    attr_reader :in_response_to, :destination
    def initialize(response, settings)
      @response = response
      @settings = settings

      @xml = Base64.decode64(@response)
      zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      @xml = zlib.inflate(@xml)
      @document = XMLSecurity::SignedDocument.new(@xml)

      @in_response_to = @document.find_first("/samlp:LogoutResponse", Onelogin::NAMESPACES)['InResponseTo'] rescue nil
      @destination = @document.find_first("/samlp:LogoutResponse", Onelogin::NAMESPACES)['Destination'] rescue nil
      @status_code = @document.find_first("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES)['Value'] rescue nil
      @status_message = @document.find_first("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES).content rescue nil
    end
    
    def logger=(val)
      @logger = val
    end
    
    def success_status?
      @status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end
  end
end
