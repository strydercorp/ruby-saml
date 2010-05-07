module Onelogin::Saml
  class MetaData
    def self.create(settings)
    %{<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{settings.issuer}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{settings.sp_slo_url}"/>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{settings.assertion_consumer_service_url}"/>
  </SPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>#{settings.tech_contact_name}</SurName>
    <EmailAddress>mailto:#{settings.tech_contact_email}</EmailAddress>
  </ContactPerson>
</EntityDescriptor>}
    end
  end
end