require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')

require 'ruby-debug'
require 'rexml/document'

describe Onelogin::Saml::Response do
  describe "decrypting assertions" do
    before :each do
      @xmlb64 = Base64.encode64(File.read(fixture_path("test1-response.xml")))
      @settings = Onelogin::Saml::Settings.new(
        :xmlsec1_path => "/usr/local/bin/xmlsec1",
        :xmlsec_certificate => fixture_path("test1-cert.pem"),
        :xmlsec_privatekey => fixture_path("test1-key.pem")
      )
    end
    
    it "should find the right attributes from an encrypted assertion" do
      @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
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
      @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
      document = REXML::Document.new(@response.document.to_s)
      REXML::XPath.first(document, "/samlp:Response/saml:Assertion").should be_nil
      @response.name_qualifier.should be_nil
    end
  end
  
  it "should use namespaces correctly to look up attributes" do
    @xmlb64 = Base64.encode64(File.read(fixture_path("test2-response.xml")))
    @settings = Onelogin::Saml::Settings.new
    @response = Onelogin::Saml::Response.new(@xmlb64, @settings)
    @response.name_id.should == "zach@example.com"
    @response.name_qualifier.should == "http://saml.example.com:8080/opensso"
    @response.session_index.should == "s2c57ee92b5ca08e93d751987d591c58acc68d2501"
    @response.status_code.should == "urn:oasis:names:tc:SAML:2.0:status:Success"
    @response.saml_attributes['eduPersonAffiliation'].should == 'member'
    @response.saml_attributes['eduPersonPrincipalName'].should == 'user@example.edu'
    @response.status_message.should == ""
  end
end
