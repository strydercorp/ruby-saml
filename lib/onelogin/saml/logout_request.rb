module Onelogin::Saml
  class LogoutRequest < BaseAssertion
    attr_writer :name_id,
                :session_index,
                :name_qualifier,
                :name_identifier_format
    attr_accessor :sp_name_qualifier

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

    def self.generate(name_qualifier, sp_name_qualifier, name_id, name_identifier_format, session_index, settings)
      super(settings, {
        destination: settings.idp_slo_target_url,
        name_identifier_format: name_identifier_format,
        name_id: name_id,
        name_qualifier: name_qualifier,
        sp_name_qualifier: sp_name_qualifier,
        session_index: session_index
      })
    end

    def generate
      name_qualifier = %{NameQualifier="#{self.name_qualifier}" } if self.name_qualifier
      sp_name_qualifier = %{SPNameQualifier="#{self.sp_name_qualifier}" } if self.sp_name_qualifier
      format = %{Format="#{self.name_identifier_format}" } if self.name_identifier_format
      <<-XML
        <samlp:LogoutRequest xmlns:samlp="#{Onelogin::NAMESPACES['samlp']}" xmlns:saml="#{Onelogin::NAMESPACES['saml']}" ID="#{self.id}" Version="2.0" IssueInstant="#{self.issue_instant}" Destination="#{CGI.escapeHTML(self.destination)}">
          <saml:Issuer>#{self.issuer}</saml:Issuer>
          <saml:NameID #{name_qualifier}#{sp_name_qualifier}#{format}>#{self.name_id}</saml:NameID>
          <samlp:SessionIndex>#{self.session_index}</samlp:SessionIndex>
        </samlp:LogoutRequest>
      XML
    end
  end
end
