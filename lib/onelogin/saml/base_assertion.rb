module Onelogin::Saml
  class BaseAssertion
    attr_accessor :settings
    attr_reader :xml
    attr_writer :id,
                :issuer,
                :issue_instant,
                :destination,
                :in_response_to,
                :base64_assertion
    def id
      @id ||= root_attribute_value('ID')
    end

    def issue_instant
      @issue_instant ||= root_attribute_value('IssueInstance')
    end

    def issuer
      @issuer ||= node_content('saml:Issuer')
    end

    def destination
      @destination ||= root_attribute_value('Destination')
    end

    def in_response_to
      @in_response_to ||= root_attribute_value('InResponseTo')
    end

    def document
      @document ||= Nokogiri::XML(xml) if xml
    end

    def xml=(value)
      @xml = value.strip
    end

    def base64_assertion
      @base64_assertion ||= begin
        deflated_assertion = Zlib::Deflate.deflate(self.xml, 9)[2..-5]
        Base64.strict_encode64(deflated_assertion)
      end
    end

    def assertion_type
      return unless document

      if document.root.name =~ /Request$/
        :request
      elsif document.root.name =~ /Response$/
        :response
      end
    end

    def process(settings)
      # TODO: Verify signature and decrypt.
    end

    def self.parse(raw_assertion, settings = nil)
      assertion = new
      assertion.base64_assertion = raw_assertion

      decoded_xml = Base64.decode64(raw_assertion)
      zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)

      assertion.xml = zlib.inflate(decoded_xml)

      assertion.process(settings) if settings
      assertion
    end

    def self.generate(settings, attributes = {})
      assertion = new

      assertion.settings = settings
      assertion.id = generate_unique_id
      assertion.issue_instant = get_timestamp
      assertion.issuer = settings.issuer

      attributes.each do |key, value|
        if assertion.respond_to? "#{key}="
          assertion.send "#{key}=", value
        end
      end

      assertion.xml = assertion.generate

      assertion
    end

    def forward_url
      @forward_url ||= begin
        url, existing_query_string = destination.split('?')
        query_string = query_string_append(existing_query_string, query_string_param, base64_assertion)

        if settings.sign?
          query_string = query_string_append(query_string, "SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
          signature =  generate_signature(query_string, settings.xmlsec_privatekey)
          query_string = query_string_append(query_string, "Signature", signature)
        end

        if settings.relay_state
          query_string = query_string_append(query_string, "RelayState", settings.relay_state)
        end

        [url, query_string].join("?")
      end
    end

    def generate
      raise "Subclass does not implement abstract method generate."
    end

    def root_attribute_value(attribute)
      document.root[attribute] if document
    end

    def node_attribute_value(xpath, attribute)
      document.root.at_xpath(xpath, Onelogin::NAMESPACES)[attribute] rescue nil
    end

    def node_content(xpath)
      document.root.at_xpath(xpath, Onelogin::NAMESPACES).content rescue nil
    end

    def self.generate_unique_id(length = 42)
      chars = ("a".."f").to_a + ("0".."9").to_a
      chars_len = chars.size
      unique_id = ("a".."f").to_a[rand(6)]
      2.upto(length) { |i| unique_id << chars[rand(chars_len)] }
      unique_id
    end

    def self.get_timestamp
      Time.new.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end

    private

    def query_string_param
      if assertion_type == :request
        'SAMLRequest'
      elsif assertion_type == :response
        'SAMLResponse'
      end
    end

    def generate_signature(string, private_key)
      pkey = OpenSSL::PKey::RSA.new(File.read(private_key))
      sign = pkey.sign(OpenSSL::Digest::SHA1.new, string)
      Base64.encode64(sign).gsub(/\s/, '')
    end

    def query_string_append(query_string, key, value)
      [query_string, "#{CGI.escape(key)}=#{CGI.escape(value)}"].compact.join('&')
    end
  end
end
