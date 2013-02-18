require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')

require 'ruby-debug'
require 'rexml/document'
require 'cgi'

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
      document = REXML::Document.new(@response.decrypted_document.to_s)
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion").should_not be_nil
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").text.should == "eMQal6uuWKMbUMbOwBfrFH90bzE="
      @response.name_qualifier.should == "http://saml.example.com:8080/opensso"
      @response.session_index.should == "s2c57ee92b5ca08e93d751987d591c58acc68d2501"
      @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
      @response.status_message.strip.should == ""
    end
    
    it "should not be able to decrypt without the proper key" do
      @settings.xmlsec_privatekey = fixture_path("wrong-key.pem")
      XMLSecurity.mute do
        @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      end
      document = REXML::Document.new(@response.document.to_s)
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion").should be_nil
      @response.name_qualifier.should be_nil
    end
  end
  
  it "should use namespaces correctly to look up attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test2-response.xml")))
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33')
    @response = Onelogin::Saml::Response.new(@xmlb64)
    @response.process(@settings)
    XMLSecurity.mute do
      @response.should_not be_is_valid # this assertion was anonymized, breaking the digital signature
    end
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
    it "should should append the saml request to a url" do
      settings = Onelogin::Saml::Settings.new(
        :xmlsec_certificate => fixture_path("test1-cert.pem"),
        :xmlsec_privatekey => fixture_path("test1-key.pem"),
        :idp_sso_target_url => "http://example.com/login.php",
        :idp_slo_target_url => "http://example.com/logout.php"
      )

      forward_url = Onelogin::Saml::AuthRequest::create(settings)
      prefix = "http://example.com/login.php?SAMLRequest="
      forward_url[0...prefix.size].should eql(prefix)

      session = { :name_qualifier => 'foo', :name_id => 'bar', :session_index => 'baz' }
      forward_url = Onelogin::Saml::LogOutRequest::create(settings, session)
      prefix = "http://example.com/logout.php?SAMLRequest="
      forward_url[0...prefix.size].should eql(prefix)
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
      forward_url[0...prefix.size].should eql(prefix)

      session = { :name_qualifier => 'foo', :name_id => 'bar', :session_index => 'baz' }
      forward_url = Onelogin::Saml::LogOutRequest::create(settings, session)
      prefix = "http://example.com/logout.php?param=foo&SAMLRequest="
      forward_url[0...prefix.size].should eql(prefix)
    end
  end
end
