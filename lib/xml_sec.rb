# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "xml/libxml"
require "openssl"
require "digest/sha1"
require "tempfile"
require "shellwords"
 
module XMLSecurity
  module SignedDocument
    attr_reader :validation_error

    def validate(idp_cert_fingerprint, logger = nil)
      # get cert from response
      base64_cert = self.find_first("//ds:X509Certificate", Onelogin::NAMESPACES).content
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert
      fingerprint = Digest::SHA1.hexdigest(cert.to_der)
      expected_fingerprint = idp_cert_fingerprint.gsub(":", "").downcase
      if fingerprint != expected_fingerprint
        @validation_error = "Invalid fingerprint (expected #{expected_fingerprint}, got #{fingerprint})"
        return false
      end

      validate_doc(base64_cert, logger)
    end

    def canonicalize_node(node)
      tmp_document = LibXML::XML::Document.new
      tmp_document.root = tmp_document.import(node)
      tmp_document.canonicalize
    end

    def validate_doc(base64_cert, logger)
      # validate references
      sig_element = find_first("//ds:Signature", { "ds" => "http://www.w3.org/2000/09/xmldsig#" })
      
      # check digests
      sig_element.find(".//ds:Reference", { "ds" => "http://www.w3.org/2000/09/xmldsig#" }).each do |ref|
        # Find the referenced element
        uri = ref["URI"]
        ref_element = find_first("//*[@ID='#{uri[1,uri.size]}']")

        # Create a copy document with it
        ref_document = LibXML::XML::Document.new
        ref_document.root = ref_document.import(ref_element)

        # Remove the Signature node
        ref_document_sig_element = ref_document.find_first(".//ds:Signature", { "ds" => "http://www.w3.org/2000/09/xmldsig#" })
        ref_document_sig_element.remove! if ref_document_sig_element

        # Canonicalize the referenced element's document
        ref_document_canonicalized = ref_document.canonicalize
        hash = Base64::encode64(Digest::SHA1.digest(ref_document_canonicalized)).chomp
        digest_value = sig_element.find_first(".//ds:DigestValue", { "ds" => "http://www.w3.org/2000/09/xmldsig#" }).content

        if hash != digest_value
          @validation_error = <<-EOF.gsub(/^\s+/, '')
            Invalid references digest.
            Got digest of
            #{hash}
            but expected
            #{digest_value}
            XML from response:
            #{ref_document.to_s(:indent => false)}
            Canonized XML:
            #{ref_document_canonicalized}
            EOF
          return false
        end
      end
 
      # verify signature
      signed_info_element = sig_element.find_first(".//ds:SignedInfo", { "ds" => "http://www.w3.org/2000/09/xmldsig#" })
      canon_string = canonicalize_node(signed_info_element)

      base64_signature = sig_element.find_first(".//ds:SignatureValue", { "ds" => "http://www.w3.org/2000/09/xmldsig#" }).content
      signature = Base64.decode64(base64_signature)

      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      if !cert.public_key.verify(OpenSSL::Digest::SHA1.new, signature, canon_string)
        @validation_error = "Invalid public key"
        return false
      end
      return true
    end

    def decrypt(settings)
      if settings.encryption_configured?
        find("//xenc:EncryptedData", Onelogin::NAMESPACES).each do |node|
          Tempfile.open("ruby-saml-decrypt") do |f|
            f.puts node.to_s
            f.close
            command = [ settings.xmlsec1_path, "decrypt", "--privkey-pem", settings.xmlsec_privatekey, f.path ].shelljoin
            decrypted_xml = %x{#{command}}
            if $?.exitstatus != 0
              @logger.warn "Could not decrypt: #{decrypted_xml}" if @logger
              return false
            else
              decrypted_doc = LibXML::XML::Document.string(decrypted_xml)
              decrypted_node = decrypted_doc.root
              decrypted_node = self.import(decrypted_node)
              node.parent.next = decrypted_node
              node.parent.remove!
            end
            f.unlink
          end
        end
      end
      true
    end
  end
end
