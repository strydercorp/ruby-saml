require File.expand_path(File.dirname(__FILE__) + '/spec_helper.rb')
require 'uri'

def verify_query_string_signature(settings, forward_url)
  url = URI.parse(forward_url)
  signed_data, signature = url.query.split('&Signature=')
  cert = OpenSSL::X509::Certificate.new(File.read(settings.xmlsec_certificate))
  cert.public_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(CGI.unescape(signature)), signed_data)
end

def verify_xml_signature(settings, forward_url)
  forward_url = URI.parse(forward_url)
  cgi_encoded_logout_request = forward_url.query.split('&').first.split('=').last
  base64_logout_request      = CGI.unescape(cgi_encoded_logout_request)
  deflated_logout_request    = Base64.decode64(base64_logout_request)
  logout_request             = inflate(deflated_logout_request)

  log_out_xml = LibXML::XML::Document.string(logout_request)
  log_out_xml.extend(XMLSecurity::SignedDocument)

  result = log_out_xml.validate(settings.idp_cert_fingerprint, nil)
  if result
    result
  else
    log_out_xml.validation_error
  end
end

# see http://stackoverflow.com/questions/1361892/how-to-decompress-gzip-string-in-ruby
def inflate(string)
  zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
  buf = zstream.inflate(string)
  zstream.finish
  zstream.close
  buf
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

  it "properly sets the Format attribute NameID based on settings" do
    settings = Onelogin::Saml::Settings.new(
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :name_identifier_format => Onelogin::Saml::NameIdentifiers::UNSPECIFIED
    )
    session = {}
    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    log_out_request.generate_request

    log_out_xml = LibXML::XML::Document.string(log_out_request.request_xml)
    log_out_xml.find_first('/samlp:LogoutRequest/saml:NameID', Onelogin::NAMESPACES).attributes['Format'].should == Onelogin::Saml::NameIdentifiers::UNSPECIFIED
  end

  it "can sign the generated request XML" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'c38e789fcfbbd4727bd8ff7fc365b44fc3596bda'
    )
    session = {}

    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    forward_url = log_out_request.generate_request

    verify_xml_signature(settings, forward_url).should == true
  end

  it "includes the certificate in the <KeyInfo> of the signature" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'c38e789fcfbbd4727bd8ff7fc365b44fc3596bda'
    )
    session = {}

    log_out_request = Onelogin::Saml::LogOutRequest.new(settings, session)
    log_out_request.generate_request

    log_out_xml = LibXML::XML::Document.string(log_out_request.request_xml)

    base64_cert_der = Base64.encode64(OpenSSL::X509::Certificate.new(File.read(settings.xmlsec_certificate)).to_der).chomp

    x509_certificate_node = log_out_xml.find_first('/samlp:LogoutRequest/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate', Onelogin::NAMESPACES)
    x509_certificate_node.should be_instance_of LibXML::XML::Node
    x509_certificate_node.content.gsub("\n", '').should == base64_cert_der.gsub("\n", '')
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
