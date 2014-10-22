require 'spec_helper'

describe Onelogin::Saml::MetaData do
  before do
    @settings = Onelogin::Saml::Settings.new(:issuer => "yourmom", :sp_slo_url => 'http://example.com/logout')
  end

  it "should have correct consumer service with one endpoint" do
    @settings.assertion_consumer_service_url = 'http://example.com/consume'
    doc = REXML::Document.new Onelogin::Saml::MetaData.create(@settings)
    service = REXML::XPath.first(doc, "//AssertionConsumerService/")
    service.attributes["index"].should == "0"
    service.attributes["Location"].should == 'http://example.com/consume'
  end

  it "should have correct consumer service with multiple endpoints" do
    @settings.assertion_consumer_service_url = ['http://example.com/consume', 'http://example.com/alt_consume']
    doc = REXML::Document.new Onelogin::Saml::MetaData.create(@settings)
    services = REXML::XPath.match(doc, "//AssertionConsumerService/")
    services[0].attributes["index"].should == "0"
    services[0].attributes["Location"].should == @settings.assertion_consumer_service_url[0]
    services[1].attributes["index"].should == "1"
    services[1].attributes["Location"].should == @settings.assertion_consumer_service_url[1]
  end

  it "publishes the public key for both encryption and signing" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    doc = REXML::Document.new Onelogin::Saml::MetaData.create(settings)
    key_descriptors = REXML::XPath.match(doc, "//KeyDescriptor")
    key_descriptors.should have(2).keys
    key_descriptors[0].attributes["use"].should == "encryption"
    key_descriptors[1].attributes["use"].should == "signing"
  end
end
