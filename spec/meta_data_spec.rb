require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')

require 'ruby-debug'
require 'rexml/document'

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

end