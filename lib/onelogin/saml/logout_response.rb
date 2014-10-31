module Onelogin::Saml
  class LogoutResponse < BaseAssertion

    STATUS_MESSAGE = 'Successfully Signed Out'

    attr_writer :status_code,
                :status_message

    def status_code
      @status_code ||= node_attribute_value('samlp:Status/samlp:StatusCode', 'Value')
    end

    def status_message
      @status_message ||= node_content("samlp:Status/samlp:StatusMessage")
    end

    def self.generate(in_response_to, settings)
      super(settings, in_response_to: in_response_to, destination: settings.idp_slo_target_url)
    end

    def generate
      <<-XML
        <samlp:LogoutResponse xmlns:samlp="#{Onelogin::NAMESPACES['samlp']}" xmlns:saml="#{Onelogin::NAMESPACES['saml']}" ID="#{self.id}" Version="2.0" IssueInstant="#{self.issue_instant}" Destination="#{self.destination}" InResponseTo="#{self.in_response_to}">
          <saml:Issuer>#{self.issuer}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="#{Onelogin::Saml::StatusCodes::SUCCESS_URI}"></samlp:StatusCode>
            <samlp:StatusMessage>#{STATUS_MESSAGE}</samlp:StatusMessage>
          </samlp:Status>
        </samlp:LogoutResponse>
      XML
    end

    def success_status?
      self.status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end
  end
end
