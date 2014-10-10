require 'spec_helper'

def verify_query_string_signature(settings, forward_url)
  url = URI.parse(forward_url)
  signed_data, signature = url.query.split('&Signature=')
  cert = OpenSSL::X509::Certificate.new(File.read(settings.xmlsec_certificate))
  cert.public_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(CGI.unescape(signature)), signed_data)
end

# see http://stackoverflow.com/questions/1361892/how-to-decompress-gzip-string-in-ruby
def inflate(string)
  zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
  buf = zstream.inflate(string)
  zstream.finish
  zstream.close
  buf
end

describe Onelogin::Saml::LogoutRequest do
  it "includes destination in the saml:LogoutRequest attributes" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}
    logout_request = Onelogin::Saml::LogoutRequest.new(settings, session)
    logout_request.generate_request

    logout_xml = LibXML::XML::Document.string(logout_request.request_xml)
    logout_xml.find_first('/samlp:LogoutRequest', Onelogin::NAMESPACES).attributes['Destination'].should ==  "http://idp.example.com/saml2"
  end

  it "properly sets the Format attribute NameID based on settings" do
    settings = Onelogin::Saml::Settings.new(
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :name_identifier_format => Onelogin::Saml::NameIdentifiers::UNSPECIFIED
    )
    session = {}
    logout_request = Onelogin::Saml::LogoutRequest.new(settings, session)
    logout_request.generate_request

    logout_xml = LibXML::XML::Document.string(logout_request.request_xml)
    logout_xml.find_first('/samlp:LogoutRequest/saml:NameID', Onelogin::NAMESPACES).attributes['Format'].should == Onelogin::Saml::NameIdentifiers::UNSPECIFIED
  end

  it "does not include the signature in the request xml" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'c38e789fcfbbd4727bd8ff7fc365b44fc3596bda'
    )
    session = {}

    logout_request = Onelogin::Saml::LogoutRequest.new(settings, session)
    logout_request.generate_request

    logout_xml = LibXML::XML::Document.string(logout_request.request_xml)
    logout_xml.find_first('/samlp:LogoutRequest/ds:Signature', Onelogin::NAMESPACES).should be_nil
  end

  it "can sign the generated query string" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33'
    )
    session = {}

    logout_request = Onelogin::Saml::LogoutRequest.new(settings, session)
    forward_url = logout_request.generate_request

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

    logout_request = Onelogin::Saml::LogoutRequest.new(settings, session)
    forward_url = logout_request.generate_request

    forward_url.should match(%r{^http://idp.example.com/saml2\?existing=param&})
    verify_query_string_signature(settings, forward_url).should be_true
  end
end
