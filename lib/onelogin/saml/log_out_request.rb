module Onelogin::Saml
  class LogOutRequest
    attr_reader :settings, :id, :request_xml, :forward_url

    def initialize(settings, session)
      @settings = settings
      @session = session
    end

    def self.create(settings, session)
      ar = LogOutRequest.new(settings, session)
      ar.generate_request
    end
    
    def generate_request
      @id = Onelogin::Saml::AuthRequest.generate_unique_id(42)
      issue_instant = Onelogin::Saml::AuthRequest.get_timestamp
      
      @request_xml = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{@id}\" Version=\"2.0\" IssueInstant=\"#{issue_instant}\"> " +
          "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{@settings.issuer}</saml:Issuer>" +
          "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" NameQualifier=\"#{@session[:name_qualifier]}\" SPNameQualifier=\"#{@settings.issuer}\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">#{@session[:name_id]}</saml:NameID>" + 
          "<samlp:SessionIndex xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">#{@session[:session_index]}</samlp:SessionIndex>" +
          "</samlp:LogoutRequest>"

      deflated_logout_request = Zlib::Deflate.deflate(@request_xml, 9)[2..-5]     
      base64_logout_request = Base64.encode64(deflated_logout_request)  
      encoded_logout_request = CGI.escape(base64_logout_request)  

      @forward_url = @settings.idp_slo_target_url + "?SAMLRequest=" + encoded_logout_request 
  
      @forward_url
    end
  end
end