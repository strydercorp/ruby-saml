require 'spec_helper'

describe Onelogin::Saml::Response do
  describe "decrypting assertions" do
    before :each do
      @xmlb64 = Base64.encode64(File.read(fixture_path("test1-response.xml")))
      @settings = Onelogin::Saml::Settings.new(
        :xmlsec_certificate => fixture_path("test1-cert.pem"),
        :xmlsec_privatekey => fixture_path("test1-key.pem"),
        :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
      )
    end

    it "should find the right attributes from an encrypted assertion" do
      @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      @response.should be_is_valid

      @response.name_id.should == "zach@zwily.com"
      @response.name_qualifier.should == "http://saml.example.com:8080/opensso"
      @response.session_index.should == "s2c57ee92b5ca08e93d751987d591c58acc68d2501"
      @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
      @response.status_message.strip.should == ""
    end

    it "support multiple valid certs" do
      @settings.idp_cert_fingerprint = ['somethingold', 'def18dbed547cdf3d52b627f41637c443045fe33']
      @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      @response.should be_is_valid
    end

    it "should not be able to decrypt without the proper key" do
      @settings.xmlsec_privatekey = fixture_path("wrong-key.pem")
      XMLSecurity.mute do
        @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      end
      document = REXML::Document.new(@response.decrypted_document.to_s)
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion").should be_nil
      @response.name_qualifier.should be_nil
    end

    it "should be able to decrypt using additional private keys" do
      @settings.xmlsec_privatekey = fixture_path("wrong-key.pem")
      @settings.xmlsec_additional_privatekeys = [fixture_path("test1-key.pem")]
      XMLSecurity.mute do
        @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      end
      document = REXML::Document.new(@response.decrypted_document.to_s)
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion").should_not be_nil
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").text.should == "eMQal6uuWKMbUMbOwBfrFH90bzE="
      @response.name_qualifier.should == "http://saml.example.com:8080/opensso"
      @response.session_index.should == "s2c57ee92b5ca08e93d751987d591c58acc68d2501"
      @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
      @response.status_message.strip.should == ""
    end
  end

  it "should not verify when XSLT transforms are being used" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test4-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'bc71f7bacb36011694405dd0e2beafcc069de45f')
    @response = Onelogin::Saml::Response.new(@xmlb64, @settings)

    XMLSecurity.mute do
      @response.should_not be_is_valid
    end

    TestServer.requests.should == []
  end

  it "should not allow external reference URIs" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test5-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'bc71f7bacb36011694405dd0e2beafcc069de45f')
    @response = Onelogin::Saml::Response.new(@xmlb64, @settings)

    XMLSecurity.mute do
      @response.should_not be_is_valid
    end

    TestServer.requests.should == []
  end

  it "should use namespaces correctly to look up attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test2-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.disable_signature_validation!(@settings)
    @response.process(@settings)
    @response.name_id.should == "zach@example.com"
    @response.name_qualifier.should == "http://saml.example.com:8080/opensso"
    @response.session_index.should == "s2c57ee92b5ca08e93d751987d591c58acc68d2501"
    @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
    @response.saml_attributes['eduPersonAffiliation'].should == 'member'
    @response.saml_attributes['eduPersonPrincipalName'].should == 'user@example.edu'
    @response.status_message.should == ""
    @response.fingerprint_from_idp.should == 'def18dbed547cdf3d52b627f41637c443045fe33'
    @response.issuer.should == 'http://saml.example.com:8080/opensso'
  end

  it "should protect against xml signature wrapping attacks targeting nameid" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("xml_signature_wrapping_attack_response_nameid.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'afe71c28ef740bc87425be13a2263d37971da1f9')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.process(@settings)
    @response.should be_is_valid
    @response.name_id.should == "_3b3e7714b72e29dc4290321a075fa0b73333a4f25f"
  end

  it "should protect against xml signature wrapping attacks targeting attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("xml_signature_wrapping_attack_response_attributes.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'afe71c28ef740bc87425be13a2263d37971da1f9')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.process(@settings)
    @response.should be_is_valid
    @response.saml_attributes['eduPersonAffiliation'].should == 'member'
    @response.saml_attributes['eduPersonPrincipalName'].should == 'student@example.edu'
  end

  it "should protect against xml signature wrapping attacks with duplicate IDs" do
    @xmlb64 = Base64.encode64(File.read(fixture_path('xml_signature_wrapping_attack_duplicate_ids.xml')))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => '7292914fc5bffa6f3fe1e43fd47c205395fecfa2')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.process(@settings)
    @response.should_not be_is_valid
  end

  it "should protect against additional mis-signed assertions" do
    @xmlb64 = Base64.encode64(File.read(fixture_path('xml_missigned_assertion.xml')))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'c38e789fcfbbd4727bd8ff7fc365b44fc3596bda')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.process(@settings)
    @response.should be_is_valid
    @response.saml_attributes['eduPersonPrincipalName'].should == 'cody'
  end

  it "should allow non-ascii characters in attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test6-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'afe71c28ef740bc87425be13a2263d37971da1f9')
    @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
    @response.should be_is_valid
    @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
    @response.saml_attributes['eduPersonAffiliation'].should == 'member'
    @response.saml_attributes['givenName'].should == 'Canvas'
    @response.saml_attributes['displayName'].should == 'Canvas Üser'
    @response.fingerprint_from_idp.should == 'afe71c28ef740bc87425be13a2263d37971da1f9'
  end

  it "should map OIDs to known attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test3-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'afe71c28ef740bc87425be13a2263d37971da1f9')
    @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
    @response.should be_is_valid
    @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
    @response.saml_attributes['eduPersonAffiliation'].should == 'member'
    @response.saml_attributes['eduPersonPrincipalName'].should == 'student@example.edu'
    @response.fingerprint_from_idp.should == 'afe71c28ef740bc87425be13a2263d37971da1f9'
  end

  it "should not throw an exception when an empty string is passed as the doc" do
    settings = Onelogin::Saml::Settings.new
    lambda {
      r = Onelogin::Saml::Response.new('foo', settings)
      r.should_not be_is_valid
    }.should_not raise_error
    lambda {
      r = Onelogin::Saml::Response.new('', settings)
      r.should_not be_is_valid
    }.should_not raise_error
  end

  describe "forward_urls" do
    let(:name_qualifier) { 'foo' }
    let(:name_id) { 'bar'}
    let(:session_index) { 'baz' }

    it "should should append the saml request to a url" do
      settings = Onelogin::Saml::Settings.new(
        :xmlsec_certificate => fixture_path("test1-cert.pem"),
        :xmlsec_privatekey => fixture_path("test1-key.pem"),
        :idp_sso_target_url => "http://example.com/login.php",
        :idp_slo_target_url => "http://example.com/logout.php"
      )

      forward_url = Onelogin::Saml::AuthRequest::create(settings)
      prefix = "http://example.com/login.php?SAMLRequest="
      expect(forward_url[0...prefix.size]).to eql(prefix)

      request = Onelogin::Saml::LogoutRequest::generate(name_qualifier, name_id, session_index, settings)
      prefix = "http://example.com/logout.php?SAMLRequest="
      expect(request.forward_url[0...prefix.size]).to eql(prefix)
    end

    it "should append the saml request to a url with query parameters" do
      settings = Onelogin::Saml::Settings.new(
        :xmlsec_certificate => fixture_path("test1-cert.pem"),
        :xmlsec_privatekey => fixture_path("test1-key.pem"),
        :idp_sso_target_url => "http://example.com/login.php?param=foo",
        :idp_slo_target_url => "http://example.com/logout.php?param=foo"
      )

      forward_url = Onelogin::Saml::AuthRequest::create(settings)
      prefix = "http://example.com/login.php?param=foo&SAMLRequest="
      expect(forward_url[0...prefix.size]).to eql(prefix)

      request = Onelogin::Saml::LogoutRequest::generate(name_qualifier, name_id, session_index, settings)
      prefix = "http://example.com/logout.php?param=foo&SAMLRequest="
      expect(request.forward_url[0...prefix.size]).to eql(prefix)
    end
  end
end
