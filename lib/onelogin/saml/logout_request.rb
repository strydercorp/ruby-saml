module Onelogin::Saml
  class LogoutRequest < BaseAssertion
    attr_writer :name_id,
                :session_index,
                :name_qualifier,
                :name_identifier_format

    def name_id
      @name_id ||= node_content('saml:NameID')
    end

    def name_identifier_format
      @name_identifier_format ||= node_attribute_value('samlp:NameID', 'Format')
    end

    def name_qualifier
      @name_qualifier ||= node_attribute_value('samlp:NameID', 'NameQualifier')
    end

    def session_index
      @session_index ||= node_content('samlp:SessionIndex')
    end

    def self.generate(name_qualifier, name_id, session_index, settings)
      super(settings, {
        destination: settings.idp_slo_target_url,
        name_identifier_format: settings.name_identifier_format,
        name_id: name_id,
        name_qualifier: name_qualifier,
        session_index: session_index
      })
    end

    def generate
      <<-XML
        <samlp:LogoutRequest xmlns:samlp="#{Onelogin::NAMESPACES['samlp']}" xmlns:saml="#{Onelogin::NAMESPACES['saml']}" ID="#{self.id}" Version="2.0" IssueInstant="#{self.issue_instant}" Destination="#{self.destination}">
          <saml:Issuer>#{self.issuer}</saml:Issuer>
          <saml:NameID NameQualifier="#{self.name_qualifier}" SPNameQualifier="#{self.issuer}" Format="#{self.name_identifier_format}">#{self.name_id}</saml:NameID>
          <samlp:SessionIndex>#{self.session_index}</samlp:SessionIndex>
        </samlp:LogoutRequest>
      XML
    end
  end
end
