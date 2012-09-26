module Onelogin::Saml
  class LogoutResponse
    
    attr_reader :settings, :document, :xml, :response
    attr_reader :status_code, :status_message, :issuer
    attr_reader :in_response_to, :destination, :request_id
    def initialize(response, settings=nil)
      @response = response

      @xml = Base64.decode64(@response)
      zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      @xml = zlib.inflate(@xml)
      @document = LibXML::XML::Document.string(@xml)

      @request_id = @document.find_first("/samlp:LogoutResponse", Onelogin::NAMESPACES)['ID'] rescue nil
      @issuer = @document.find_first("/samlp:LogoutResponse/saml:Issuer", Onelogin::NAMESPACES).content rescue nil
      @in_response_to = @document.find_first("/samlp:LogoutResponse", Onelogin::NAMESPACES)['InResponseTo'] rescue nil
      @destination = @document.find_first("/samlp:LogoutResponse", Onelogin::NAMESPACES)['Destination'] rescue nil
      @status_code = @document.find_first("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES)['Value'] rescue nil
      @status_message = @document.find_first("/samlp:LogoutResponse/samlp:Status/samlp:StatusMessage", Onelogin::NAMESPACES).content rescue nil

      process(settings) if settings
    end

    def process(settings)
      @settings = settings
      return unless @response
    end

    def logger=(val)
      @logger = val
    end
    
    def success_status?
      @status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end
  end
end
