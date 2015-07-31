require 'spec_helper'
require 'rexml/document'
require 'cgi'

describe Onelogin::Saml::LogoutResponse do
  let(:id) { Onelogin::Saml::LogoutResponse.generate_unique_id(42) }
  let(:issue_instant) { Onelogin::Saml::LogoutResponse.get_timestamp }
  let(:in_response_to) { Onelogin::Saml::LogoutResponse.generate_unique_id(42) }
  let(:idp_slo_target_url) { 'http://idp.example.com/saml2?existing=param&existing=param' }
  let(:issuer) { 'http://idp.example.com/saml2?existing=param&existing=param' }
  let(:session) { {} }

  let(:settings) do
    Onelogin::Saml::Settings.new(
      idp_slo_target_url: idp_slo_target_url,
      issuer: issuer
    )
  end

  let(:xml) do
    allow(Onelogin::Saml::LogoutResponse).to receive(:generate_unique_id).and_return(id)
    allow(Onelogin::Saml::LogoutResponse).to receive(:get_timestamp).and_return(issue_instant)

    Onelogin::Saml::LogoutResponse::generate(in_response_to, settings).document
  end

  it "includes destination in the saml:LogoutRequest attributes" do
    value = xml.at_xpath('/samlp:LogoutResponse', Onelogin::NAMESPACES)['Destination']
    expect(value).to eq "http://idp.example.com/saml2?existing=param&existing=param"
  end

  it "includes id in the saml:LogoutRequest attributes" do
    value = xml.at_xpath('/samlp:LogoutResponse', Onelogin::NAMESPACES)['ID']
    expect(value).to eq id
  end

  it "includes issue_instant in the saml:LogoutRequest attributes" do
    value = xml.at_xpath('/samlp:LogoutResponse', Onelogin::NAMESPACES)['IssueInstant']
    expect(value).to eq issue_instant
  end

  it "includes in_response_to in the saml:LogoutRequest attributes" do
    value = xml.at_xpath('/samlp:LogoutResponse', Onelogin::NAMESPACES)['InResponseTo']
    expect(value).to eq in_response_to
  end

  it "includes issuer tag" do
    value = xml.at_xpath("/samlp:LogoutResponse/saml:Issuer", Onelogin::NAMESPACES).content
    expect(value).to eq issuer
  end

  it "includes status code tag" do
    value = xml.at_xpath("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES)['Value']
    expect(value).to eq Onelogin::Saml::StatusCodes::SUCCESS_URI
  end

  it "includes status message tag" do
    value = xml.at_xpath("/samlp:LogoutResponse/samlp:Status/samlp:StatusMessage", Onelogin::NAMESPACES).content
    expect(value).to eq Onelogin::Saml::LogoutResponse::STATUS_MESSAGE
  end

  it "should use namespaces correctly to look up attributes" do
    xml = Zlib::Deflate.deflate(File.read(fixture_path("logout_response.xml")), 9)[2..-5]

    xmlb64 = Base64.encode64(xml)
    settings = Onelogin::Saml::Settings.new(:idp_cert_fingerprint => 'def18dbed547cdf3d52b627f41637c443045fe33')
    response = Onelogin::Saml::LogoutResponse::parse(xmlb64, settings)

    expect(response.id).to eq '_cbb63e9741259e3f1c98a1ae38ac5ac25889720b32'
    expect(response.issuer).to eq 'http://saml.example.com:8080/opensso'
    expect(response.in_response_to).to eq "_72424ea37e28763e351189529639b9c2b150ff37e5"
    expect(response.destination).to eq "http://saml.example.com:8080/opensso/SingleLogoutService"
    expect(response.status_code).to eq Onelogin::Saml::StatusCodes::SUCCESS_URI
    expect(response.status_message).to eq "Successfully logged out from service"
  end
end
