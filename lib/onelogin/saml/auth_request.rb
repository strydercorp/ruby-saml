module Onelogin::Saml
  class AuthRequest < BaseAssertion
    attr_accessor :requested_authn_context,
                  :assertion_consumer_service_url,
                  :name_identifier_format

    def self.parse(raw_assertion, settings = nil)
      raise NotImplementedError
    end

    def self.generate(settings)
      super(settings, {
        destination: settings.idp_sso_target_url,
        requested_authn_context: settings.requested_authn_context,
        assertion_consumer_service_url: Array(settings.assertion_consumer_service_url).first,
        name_identifier_format: settings.name_identifier_format
      })
    end

    def generate
      if self.requested_authn_context
        xml = <<-XML
          <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef>#{self.requested_authn_context}</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        XML
      end

      <<-XML
        <samlp:AuthnRequest
          xmlns:samlp="#{Onelogin::NAMESPACES['samlp']}"
          xmlns:saml="#{Onelogin::NAMESPACES['saml']}"
          ID="#{self.id}"
          Version="2.0"
          ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          AssertionConsumerServiceURL=\"#{self.assertion_consumer_service_url}\"
          IssueInstant="#{self.issue_instant}">

          <saml:Issuer>#{self.issuer}</saml:Issuer>
          <samlp:NameIDPolicy Format="#{self.name_identifier_format}" AllowCreate="true"></samlp:NameIDPolicy>

          #{xml}
        </samlp:AuthnRequest>
      XML
    end
  end
end
