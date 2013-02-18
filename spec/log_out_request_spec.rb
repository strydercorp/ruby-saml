require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')
require 'uri'

def verify_query_string_signature(settings, forward_url)
  url = URI.parse(forward_url)
  signed_data, signature = url.query.split('&Signature=')
  cert = OpenSSL::X509::Certificate.new(File.read(settings.xmlsec_certificate))
  cert.public_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(CGI.unescape(signature)), signed_data)
end

describe Onelogin::Saml::LogOutRequest do
  it "includes destination in the saml:LogoutRequest attributes" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}
    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    log_out_request.generate_request

    log_out_xml = LibXML::XML::Document.string(log_out_request.request_xml)
    log_out_xml.find_first('/samlp:LogoutRequest', Onelogin::NAMESPACES).attributes['Destination'].should ==  "http://idp.example.com/saml2"
  end

  it "can sign the generated request XML" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}

    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    log_out_request.generate_request

    log_out_xml = LibXML::XML::Document.string(log_out_request.request_xml)
    log_out_xml.find_first('/samlp:LogoutRequest/ds:Signature/ds:SignatureValue', Onelogin::NAMESPACES).should_not be_nil
  end

  it "can sign the generated query string" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}

    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    forward_url = log_out_request.generate_request

    verify_query_string_signature(settings, forward_url).should be_true
  end

  it "properly signs when the IDP URL already contains a query string" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2?existing=param",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}

    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    forward_url = log_out_request.generate_request
    
    forward_url.should match(%r{^http://idp.example.com/saml2\?existing=param&})
    verify_query_string_signature(settings, forward_url).should be_true
  end
end
