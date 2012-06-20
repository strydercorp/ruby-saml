module Onelogin::Saml
  class AuthRequest
    
    attr_reader :settings, :id, :request_xml, :forward_url
    
    def initialize(settings)
      @settings = settings
    end
    
    def self.create(settings)
      ar = AuthRequest.new(settings)
      ar.generate_request
    end
    
    def generate_request
      @id = Onelogin::Saml::AuthRequest.generate_unique_id(42)
      issue_instant = Onelogin::Saml::AuthRequest.get_timestamp

      @request_xml = 
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{@id}\" Version=\"2.0\" IssueInstant=\"#{issue_instant}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"#{Array(settings.assertion_consumer_service_url).first}\">" +
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{@settings.issuer}</saml:Issuer>\n" +
        "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"#{@settings.name_identifier_format}\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n"
      
      if @settings.requested_authn_context
        @request_xml += "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">"
        @request_xml += "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{@settings.requested_authn_context}</saml:AuthnContextClassRef>"
        @request_xml += "</samlp:RequestedAuthnContext>\n"
      end
        
      @request_xml += "</samlp:AuthnRequest>"

      deflated_request  = Zlib::Deflate.deflate(@request_xml, 9)[2..-5]     
      base64_request    = Base64.encode64(deflated_request)  
      encoded_request   = CGI.escape(base64_request)

      @forward_url = @settings.idp_sso_target_url + (@settings.idp_sso_target_url.include?("?") ? "&" : "?") + "SAMLRequest=" + encoded_request
    end
    
    private 
    
    def self.generate_unique_id(length)
      chars = ("a".."f").to_a + ("0".."9").to_a
      chars_len = chars.size
      unique_id = ("a".."f").to_a[rand(6)]
      2.upto(length) { |i| unique_id << chars[rand(chars_len)] }
      unique_id
    end
    
    def self.get_timestamp
      Time.new.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end
  end
end
