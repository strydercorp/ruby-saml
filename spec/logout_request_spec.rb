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
  let(:settings) do
    Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33',
      :name_identifier_format => Onelogin::Saml::NameIdentifiers::UNSPECIFIED
    )
  end

  let(:name_qualifier) { 'foo' }
  let(:sp_name_qualifier) { 'foo' }
  let(:name_id) { 'bar'}
  let(:name_identifier_format) { Onelogin::Saml::NameIdentifiers::UNSPECIFIED }
  let(:session_index) { 'baz' }

  let(:logout_request) do
    Onelogin::Saml::LogoutRequest::generate(
      name_qualifier,
      sp_name_qualifier,
      name_id,
      name_identifier_format,
      session_index,
      settings
    )
  end

  let(:forward_url) { logout_request.forward_url }

  it "includes destination in the saml:LogoutRequest attributes" do
    logout_xml = Nokogiri::XML(logout_request.xml)
    logout_xml.at_xpath('/samlp:LogoutRequest', Onelogin::NAMESPACES)['Destination'].should ==  "http://idp.example.com/saml2"
  end

  it "properly sets the Format attribute NameID based on settings" do
    logout_xml = Nokogiri::XML(logout_request.xml)
    logout_xml.at_xpath('/samlp:LogoutRequest/saml:NameID', Onelogin::NAMESPACES)['Format'].should == Onelogin::Saml::NameIdentifiers::UNSPECIFIED
  end

  it "does not include attribues when they are nil" do
    logout_request = Onelogin::Saml::LogoutRequest::generate(
      nil,
      nil,
      name_id,
      nil,
      session_index,
      settings
    )
    logout_xml = Nokogiri::XML(logout_request.xml)
    name_id_elem = logout_xml.at_xpath('/samlp:LogoutRequest/saml:NameID', Onelogin::NAMESPACES)
    name_id_elem['NameQualifier'].should == nil
    name_id_elem['SPNameQualifier'].should == nil
    name_id_elem['NameIdentifierFormat'].should == nil
  end

  it "does not include the signature in the request xml" do
    logout_xml = Nokogiri::XML(logout_request.xml)
    logout_xml.at_xpath('/samlp:LogoutRequest/ds:Signature', Onelogin::NAMESPACES).should be_nil
  end

  it "can sign the generated query string" do
    expect(verify_query_string_signature(settings, forward_url)).to eq true
  end

  it "properly signs when the IDP URL already contains a query string" do
    settings = Onelogin::Saml::Settings.new(
      :xmlsec_certificate => fixture_path("test1-cert.pem"),
      :xmlsec_privatekey => fixture_path("test1-key.pem"),
      :idp_slo_target_url => "http://idp.example.com/saml2?existing=param&existing=param",
      :idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33',
      :name_identifier_format => Onelogin::Saml::NameIdentifiers::UNSPECIFIED
    )
    request = Onelogin::Saml::LogoutRequest.generate(name_qualifier,
                                                     sp_name_qualifier,
                                                     name_id,
                                                     name_identifier_format,
                                                     session_index,
                                                     settings)
    expect(request.forward_url).to match(%r{^http://idp.example.com/saml2\?existing=param\&existing=param&})
    expect(verify_query_string_signature(settings, request.forward_url)).to eq true
  end

  it "parses a logout request" do
    xml = Zlib::Deflate.deflate(File.read(fixture_path("logout_request.xml")), 9)[2..-5]

    xmlb64 = Base64.encode64(xml)
    settings = Onelogin::Saml::Settings.new
    request = Onelogin::Saml::LogoutRequest::parse(xmlb64)

    expect(request.id).to eq '_cbb63e9741259e3f1c98a1ae38ac5ac25889720b32'
    expect(request.issuer).to eq 'http://saml.example.com:8080/opensso'
    expect(request.name_id).to eq '_6a171f538d4f733ae95eca74ce264cfb602808c850'
    expect(request.session_index).to eq '_b976de57fcf0f707de297069f33a6b0248827d96a9'
  end
end
