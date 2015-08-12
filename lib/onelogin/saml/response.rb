module Onelogin::Saml
  class Response

    attr_accessor :settings
    attr_reader :document, :xml, :response
    attr_reader :name_id, :name_qualifier, :session_index, :saml_attributes
    attr_reader :status_code, :status_message
    attr_reader :in_response_to, :destination, :issuer
    attr_reader :validation_error

    def initialize(response, settings=nil)
      @response = response

      begin
        @xml = Base64.decode64(@response)
        @document = Nokogiri::XML(@xml)
        @document.extend(XMLSecurity::SignedDocument)
      rescue
        # could not parse document, everything is invalid
        @response = nil
        return
      end

      @issuer = document.at_xpath("/samlp:Response/saml:Issuer", Onelogin::NAMESPACES).content.strip rescue nil
      @issuer ||= document.at_xpath("/samlp:Response/saml:Assertion/saml:Issuer", Onelogin::NAMESPACES).content.strip rescue nil
      @status_code = document.at_xpath("/samlp:Response/samlp:Status/samlp:StatusCode", Onelogin::NAMESPACES)["Value"] rescue nil

      process(settings) if settings
    end

    def process(settings)
      @settings = settings
      @logger = settings.logger
      return unless @response

      @in_response_to = untrusted_find_first("/samlp:Response")['InResponseTo'] rescue nil
      @destination    = untrusted_find_first("/samlp:Response")['Destination'] rescue nil
      @status_message = untrusted_find_first("/samlp:Response/samlp:Status/samlp:StatusCode").content rescue nil

      @name_id        = trusted_find_first("saml:Assertion/saml:Subject/saml:NameID").content rescue nil
      @name_qualifier = trusted_find_first("saml:Assertion/saml:Subject/saml:NameID")["NameQualifier"] rescue nil
      @session_index  = trusted_find_first("saml:Assertion/saml:AuthnStatement")["SessionIndex"] rescue nil

      @saml_attributes = {}
      trusted_find("saml:Attribute").each do |attr|
        attrname = attr['FriendlyName'] || Onelogin::ATTRIBUTES[attr['Name']] || attr['Name']
        @saml_attributes[attrname] = attr.content.strip rescue nil
      end
    end

    def disable_signature_validation!(settings)
      @settings      = settings
      @is_valid      = true
      @trusted_roots = [decrypted_document.root]
    end

    def decrypted_document
      @decrypted_document ||= document.clone.tap do |doc|
        doc.extend(XMLSecurity::SignedDocument)
        doc.decrypt!(settings)
      end
    end

    def untrusted_find_first(xpath)
      decrypted_document.at_xpath(xpath, Onelogin::NAMESPACES)
    end

    def trusted_find_first(xpath)
      trusted_find(xpath).first
    end

    def trusted_find(xpath)
      trusted_roots.map do |trusted_root|
        trusted_root.xpath("descendant-or-self::#{xpath}", Onelogin::NAMESPACES).to_a
      end.flatten.compact
    end

    def is_valid?
      @is_valid ||= validate
    end

    def validate
      if response.nil? || response == ""
        @validation_error = "No response to validate"
        return false
      end

      if !settings.idp_cert_fingerprint
        @validation_error = "No fingerprint configured in SAML settings"
        return false
      end

      # Verify the original document if it has a signature, otherwise verify the signature
      # in the encrypted portion. If there is no signature, then we can't verify.
      verified = false

      if document.has_signature?
        verified = document.validate(settings.idp_cert_fingerprint, @logger)
        if !verified
          @validation_error = document.validation_error
          return false
        end
      end

      if !verified && decrypted_document.has_signature?
        verified = decrypted_document.validate(settings.idp_cert_fingerprint, @logger)
        if !verified
          @validation_error = decrypted_document.validation_error
          return false
        end
      end

      if !verified
        @validation_error = "No signature found in the response"
        return false
      end

      # If we get here, validation has succeeded, and we can trust all
      # <ds:Signature> elements. Each of those has a <ds:Reference> which
      # points to the root of the root of the NodeSet it signs.
      @trusted_roots = decrypted_document.signed_roots

      true
    end

    # triggers validation
    def trusted_roots
      is_valid? ? @trusted_roots : []
    end

    def success_status?
      @status_code == Onelogin::Saml::StatusCodes::SUCCESS_URI
    end

    def auth_failure?
      @status_code == Onelogin::Saml::StatusCodes::AUTHN_FAILED_URI
    end

    def no_authn_context?
      @status_code == Onelogin::Saml::StatusCodes::NO_AUTHN_CONTEXT_URI
    end

    def fingerprint_from_idp
      if base64_cert = decrypted_document.at_xpath("//ds:X509Certificate", Onelogin::NAMESPACES)
        cert_text = Base64.decode64(base64_cert.content)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der)
      else
        nil
      end
    end
  end
end
