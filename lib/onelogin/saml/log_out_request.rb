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
      
      @request_xml = <<-REQUEST_XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="#{@id}" Version="2.0" IssueInstant="#{issue_instant}" Destination="#{@settings.idp_slo_target_url}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{@settings.issuer}</saml:Issuer>
  <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="#{@session[:name_qualifier]}" SPNameQualifier="#{@settings.issuer}" Format="#{@settings.name_identifier_format}">#{@session[:name_id]}</saml:NameID>
  <samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">#{@session[:session_index]}</samlp:SessionIndex>
</samlp:LogoutRequest>
      REQUEST_XML

      if settings.sign?
        @request_xml = XMLSecurity.sign(@id, @request_xml, @settings.xmlsec_privatekey, @settings.xmlsec_certificate)
      end

      deflated_logout_request = Zlib::Deflate.deflate(@request_xml, 9)[2..-5]
      base64_logout_request = Base64.encode64(deflated_logout_request)

      url, existing_query_string = @settings.idp_slo_target_url.split('?')
      query_string = _query_string_append(existing_query_string, 'SAMLRequest', base64_logout_request)

      if settings.sign?
        query_string = _query_string_append(query_string, "SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        signature =  _generate_signature(query_string, @settings.xmlsec_privatekey)
        query_string = _query_string_append(query_string, "Signature", signature)
      end

      @forward_url = [url, query_string].join("?")
  
      @forward_url
    end

    def _generate_signature(string, private_key)
      pkey = OpenSSL::PKey::RSA.new(File.read(private_key))
      sign = pkey.sign(OpenSSL::Digest::SHA1.new, string)
      Base64.encode64(sign).gsub(/\s/, '')
    end

    def _query_string_append(query_string, key, value)
      [query_string, "#{CGI.escape(key)}=#{CGI.escape(value)}"].compact.join('&')
    end
  end
end
