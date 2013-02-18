require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')

require 'ruby-debug'
require 'rexml/document'
require 'cgi'

describe Onelogin::Saml::LogoutResponse do
  it "should use namespaces correctly to look up attributes" do
    @xml = Zlib::Deflate.deflate(File.read(fixture_path("test_logout_response.xml")), 9)[2..-5]

    @xmlb64 = Base64.encode64(@xml)
    @settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33')
    @response = Onelogin::Saml::LogoutResponse.new(@xmlb64)
    @response.process(@settings)

    @response.request_id.should == '_cbb63e9741259e3f1c98a1ae38ac5ac25889720b32'
    @response.issuer.should == 'http://saml.example.com:8080/opensso'
    @response.in_response_to.should == "_72424ea37e28763e351189529639b9c2b150ff37e5"
    @response.destination.should == "http://saml.example.com:8080/opensso/SingleLogoutService"
    @response.status_code.should == Onelogin::Saml::StatusCodes::SUCCESS_URI
    @response.status_message.should == "Successfully logged out from service"
  end

end
