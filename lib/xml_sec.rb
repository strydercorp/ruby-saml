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
require 'ffi'
require 'base64'
require "nokogiri"
require "openssl"
require "digest/sha1"

module XMLSecurity
  extend FFI::Library
  ffi_lib "xmlsec1-openssl"

  enum :xmlSecKeyDataFormat, [
      :xmlSecKeyDataFormatUnknown,
      :xmlSecKeyDataFormatBinary,
      :xmlSecKeyDataFormatPem,
      :xmlSecKeyDataFormatDer,
      :xmlSecKeyDataFormatPkcs8Pem,
      :xmlSecKeyDataFormatPkcs8Der,
      :xmlSecKeyDataFormatPkcs12,
      :xmlSecKeyDataFormatCertPem,
      :xmlSecKeyDataFormatCertDer
  ]

  enum :xmlSecKeyInfoMode, [
      :xmlSecKeyInfoModeRead,
      :xmlSecKeyInfoModeWrite
  ]

  enum :xmlSecAllocMode, [
      :xmlSecAllocModeExact,
      :xmlSecAllocModeDouble
  ]

  enum :xmlSecTransformStatus, [
      :xmlSecTransformStatusNone,
      :xmlSecTransformStatusWorking,
      :xmlSecTransformStatusFinished,
      :xmlSecTransformStatusOk,
      :xmlSecTransformStatusFail
  ]

  enum :xmlSecTransformOperation, [
      :xmlSecTransformOperationNone, 0,
      :xmlSecTransformOperationEncode,
      :xmlSecTransformOperationDecode,
      :xmlSecTransformOperationSign,
      :xmlSecTransformOperationVerify,
      :xmlSecTransformOperationEncrypt,
      :xmlSecTransformOperationDecrypt
  ]

  enum :xmlSecDSigStatus, [
      :xmlSecDSigStatusUnknown, 0,
      :xmlSecDSigStatusSucceeded,
      :xmlSecDSigStatusInvalid
  ]

  XMLSEC_ERRORS_R_INVALID_DATA = 12
  class XmlSecError < ::RuntimeError; end

  class XmlSecPtrList < FFI::Struct
    layout \
      :id,                          :pointer,
      :data,                        :pointer,        # xmlSecPtr*
      :use,                         :uint,
      :max,                         :uint,
      :allocMode,                   :xmlSecAllocMode
  end

  class XmlSecKeyReq < FFI::Struct
    layout \
      :keyId,                       :string,         # xmlSecKeyDataId
      :keyType,                     :uint,           # xmlSecKeyDataType
      :keyUsage,                    :uint,           # xmlSecKeyUsage
      :keyBitsSize,                 :uint,           # xmlSecSize
      :keyUseWithList,              XmlSecPtrList,
      :reserved1,                   :pointer,        # void *
      :reserved2,                   :pointer         # void *
  end

  class XmlSecTransformCtx < FFI::Struct
    layout \
      :userData,                    :pointer,        # void *
      :flags,                       :uint,
      :flags2,                      :uint,
      :enabledUris,                 :uint,
      :enabledTransforms,           XmlSecPtrList,
      :preExecCallback,             :pointer,        # xmlSecTransformCtxPreExecuteCallback
      :result,                      :pointer,        # xmlSecBufferPtr
      :status,                      :xmlSecTransformStatus,
      :uri,                         :string,
      :xptrExpr,                    :string,
      :first,                       :pointer,        # xmlSecTransformPtr
      :last,                        :pointer,        # xmlSecTransformPtr
      :reserved0,                   :pointer,        # void *
      :reserved1,                   :pointer         # void *
  end

  class XmlSecTransformUriType
    None         = 0x0000
    Empty        = 0x0001
    SameDocument = 0x0002
    Local        = 0x0004
    Remote       = 0x0008
    Any          = 0xFFFF

    def self.conservative
      (Empty | SameDocument)
    end
  end

  class XmlSecKeyInfoCtx < FFI::Struct
    layout \
      :userDate,                    :pointer,
      :flags,                       :uint,
      :flags2,                      :uint,
      :keysMngr,                    :pointer,
      :mode,                        :xmlSecKeyInfoMode,
      :enabledKeyData,              XmlSecPtrList,
      :base64LineSize,              :int,
      :retrievalMethodCtx,          XmlSecTransformCtx,
      :maxRetrievalMethodLevel,     :int,
      :encCtx,                      :pointer,
      :maxEncryptedKeyLevel,        :int,
      :certsVerificationTime,       :time_t,
      :certsVerificationDepth,      :int,
      :pgpReserved,                 :pointer,
      :curRetrievalMethodLevel,     :int,
      :curEncryptedKeyLevel,        :int,
      :keyReq,                      XmlSecKeyReq,
      :reserved0,                   :pointer,
      :reserved1,                   :pointer
  end

  class XmlSecDSigCtx < FFI::Struct
    layout \
      :userData,                    :pointer,     # void *
      :flags,                       :uint,
      :flags2,                      :uint,
      :keyInfoReadCtx,              XmlSecKeyInfoCtx.by_value,
      :keyInfoWriteCtx,             XmlSecKeyInfoCtx.by_value,
      :transformCtx,                XmlSecTransformCtx.by_value,
      :enabledReferenceUris,        :uint,        # xmlSecTransformUriType
      :enabledReferenceTransforms,  XmlSecPtrList.by_ref,     # xmlSecPtrListPtr
      :referencePreExecuteCallback, :pointer,     # xmlSecTransformCtxPreExecuteCallback
      :defSignMethodId,             :string,      # xmlSecTransformId
      :defC14NMethodId,             :string,      # xmlSecTransformId
      :defDigestMethodId,           :string,      # xmlSecTransformId

      :signKey,                     :pointer,     # xmlSecKeyPtr
      :operation,                   :xmlSecTransformOperation,
      :result,                      :pointer,     # xmlSecBufferPtr
      :status,                      :xmlSecDSigStatus,
      :signMethod,                  :pointer,     # xmlSecTransformPtr
      :c14nMethod,                  :pointer,     # xmlSecTransformPtr
      :preSignMemBufMethod,         :pointer,     # xmlSecTransformPtr
      :signValueNode,               :pointer,     # xmlNodePtr
      :id,                          :string,
      :signedInfoReferences,        XmlSecPtrList,
      :manifestReferences,          XmlSecPtrList,
      :reserved0,                   :pointer,
      :reserved1,                   :pointer
  end

  ErrorCallback = FFI::Function.new(:void,
      [ :string, :int, :string, :string,     :string,      :int,   :string ]
  ) do |file,    line, func,    errorObject, errorSubject, reason, msg     |
    XMLSecurity.handle_xmlsec_error_callback(file, line, func, errorObject, errorSubject, reason, msg)
  end

  # xmlsec functions
  attach_function :xmlSecInit, [], :int
  attach_function :xmlSecParseMemory, [ :pointer, :uint, :int ], :pointer
  attach_function :xmlSecFindNode, [ :pointer, :string, :string ], :pointer
  attach_function :xmlSecDSigCtxCreate, [ :pointer ], XmlSecDSigCtx.by_ref
  attach_function :xmlSecDSigCtxVerify, [ XmlSecDSigCtx.by_ref, :pointer ], :int
  attach_function :xmlSecOpenSSLInit, [], :int
  attach_function :xmlSecOpenSSLAppInit, [ :pointer ], :int
  attach_function :xmlSecAddIDs, [ :pointer, :pointer, :pointer ], :void
  attach_function :xmlSecDSigCtxDestroy, [ XmlSecDSigCtx.by_ref ], :void

  attach_function :xmlSecKeysMngrCreate, [], :pointer
  attach_function :xmlSecOpenSSLAppDefaultKeysMngrInit, [ :pointer ], :int
  attach_function :xmlSecOpenSSLAppKeyLoad, [ :string, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
  attach_function :xmlSecOpenSSLAppKeyCertLoad, [ :pointer, :string, :xmlSecKeyDataFormat], :int
  attach_function :xmlSecOpenSSLAppKeyLoadMemory, [ :pointer, :uint, :xmlSecKeyDataFormat, :pointer, :pointer, :pointer ], :pointer
  attach_function :xmlSecOpenSSLAppDefaultKeysMngrAdoptKey, [ :pointer, :pointer ], :int
  attach_function :xmlSecKeysMngrDestroy, [ :pointer ], :void

  attach_function :xmlSecEncCtxCreate, [ :pointer ], :pointer
  attach_function :xmlSecEncCtxDecrypt, [ :pointer, :pointer ], :int
  attach_function :xmlSecEncCtxDestroy, [ :pointer ], :void

  attach_function :xmlSecErrorsDefaultCallback, [ :string, :int, :string, :string, :string, :int, :string ], :void
  attach_function :xmlSecErrorsDefaultCallbackEnableOutput, [ :bool ], :void
  attach_function :xmlSecErrorsSetCallback, [:pointer], :void

  attach_function :xmlSecTransformExclC14NGetKlass, [], :pointer
  attach_function :xmlSecOpenSSLTransformRsaSha1GetKlass, [], :pointer
  attach_function :xmlSecOpenSSLTransformSha1GetKlass, [], :pointer

  attach_function :xmlSecTmplSignatureCreate, [ :pointer, :pointer, :pointer, :string ], :pointer
  attach_function :xmlSecTmplSignatureAddReference, [ :pointer, :pointer, :pointer, :pointer, :pointer ], :pointer
  attach_function :xmlSecTransformEnvelopedGetKlass, [], :pointer
  attach_function :xmlSecTmplSignatureEnsureKeyInfo, [ :pointer, :pointer ], :pointer
  attach_function :xmlSecTmplReferenceAddTransform, [ :pointer, :pointer ], :pointer

  attach_function :xmlSecKeySetName, [ :pointer, :string ], :int

  attach_function :xmlSecTmplKeyInfoAddKeyName, [ :pointer, :pointer ], :pointer
  attach_function :xmlSecTmplKeyInfoAddX509Data, [ :pointer ], :pointer

  attach_function :xmlSecDSigCtxSign, [ :pointer, :pointer ], :int

  attach_function :xmlSecDSigCtxEnableReferenceTransform, [ :pointer, :pointer ], :int
  attach_function :xmlSecPtrListAdd, [ :pointer, :pointer ], :int
  attach_function :xmlSecPtrListGetItem, [ :pointer, :uint ], :pointer
  attach_function :xmlSecPtrListGetSize, [ :pointer ], :uint
  attach_function :xmlSecTransformIdsGet, [], :pointer
  attach_function :xmlSecTransformXsltGetKlass, [], :pointer

  # libxml functions
  attach_function :xmlInitParser, [], :void
  attach_function :xmlDocGetRootElement, [ :pointer ], :pointer
  attach_function :xmlDocDumpFormatMemory, [ :pointer, :pointer, :pointer, :int ], :void
  attach_function :xmlFreeDoc, [ :pointer ], :void
  attach_function :xmlParseMemory, [ :pointer, :int ], :pointer
  attach_function :xmlAddChild, [ :pointer, :pointer ], :pointer

  attach_variable :__xmlFree, :xmlFree, callback([ :pointer ], :void)
  attach_variable :__xmlMalloc, :xmlMalloc, callback([ :size_t ], :pointer)

  def self.xmlMalloc(size)
    __xmlMalloc.call(size)
  end

  def self.xmlFree(ptr)
    __xmlFree.call(ptr)
  end

  self.xmlInitParser
  raise "Failed initializing XMLSec" if self.xmlSecInit < 0
  raise "Failed initializing app crypto" if self.xmlSecOpenSSLAppInit(nil) < 0
  raise "Failed initializing crypto" if self.xmlSecOpenSSLInit < 0
  self.xmlSecErrorsSetCallback(ErrorCallback)

  def self.handle_xmlsec_error_callback(*args)
    raise_exception_if_necessary(*args)
    xmlSecErrorsDefaultCallback(*args)
  end

  def self.raise_exception_if_necessary(file, line, func, errorObject, errorSubject, reason, msg)
    if reason == XMLSEC_ERRORS_R_INVALID_DATA
      raise XmlSecError.new(msg)
    end
  end


  def self.mute(&block)
    xmlSecErrorsDefaultCallbackEnableOutput(false)
    block.call
    xmlSecErrorsDefaultCallbackEnableOutput(true)
  end

  def self.disable_xslt_transforms!(dsig_context)
    all_transforms = XMLSecurity.xmlSecTransformIdsGet

    (0...XMLSecurity.xmlSecPtrListGetSize(all_transforms)).each do |pos|
      transform = XMLSecurity.xmlSecPtrListGetItem(all_transforms, pos)
      unless transform == XMLSecurity.xmlSecTransformXsltGetKlass
        XMLSecurity.xmlSecPtrListAdd(dsig_context[:transformCtx][:enabledTransforms], transform)
        XMLSecurity.xmlSecDSigCtxEnableReferenceTransform(dsig_context, transform)
      end
    end
  end

  def self.disable_remote_references!(dsig_context)
    dsig_context[:transformCtx][:enabledUris] = XmlSecTransformUriType.conservative
    dsig_context[:enabledReferenceUris] = XmlSecTransformUriType.conservative
  end

  module SignedDocument
    attr_reader :validation_error

    def self.format_cert(cert)
      # re-encode the certificate in the proper format
      # this snippet is from http://bugs.ruby-lang.org/issues/4421
      rsa = cert.public_key
      modulus = rsa.n
      exponent = rsa.e
      oid = OpenSSL::ASN1::ObjectId.new("rsaEncryption")
      alg_id = OpenSSL::ASN1::Sequence.new([oid, OpenSSL::ASN1::Null.new(nil)])
      ary = [OpenSSL::ASN1::Integer.new(modulus), OpenSSL::ASN1::Integer.new(exponent)]
      pub_key = OpenSSL::ASN1::Sequence.new(ary)
      enc_pk = OpenSSL::ASN1::BitString.new(pub_key.to_der)
      subject_pk_info = OpenSSL::ASN1::Sequence.new([alg_id, enc_pk])
      base64 = Base64.encode64(subject_pk_info.to_der)

      # This is the equivalent to the X.509 encoding used in >= 1.9.3
      "-----BEGIN PUBLIC KEY-----\n#{base64}-----END PUBLIC KEY-----"
    end

    def has_signature?
      signatures.any?
    end

    def signed_roots
      signatures.map do |sig|
        ref = sig.at_xpath('./ds:SignedInfo/ds:Reference', Onelogin::NAMESPACES)
        signed_element_id = ref['URI'].sub(/^#/, '')

        if signed_element_id.empty?
          self.root
        else
          xpath_id_query = %Q(ancestor::*[@ID = "#{signed_element_id}"])

          ref.at_xpath(xpath_id_query, Onelogin::NAMESPACES)
        end
      end.compact
    end

    def signatures
      # we only return the first, cause our signature validation only checks the first
      @signatures ||= [self.at_xpath("//ds:Signature", Onelogin::NAMESPACES)].compact
    end

    def validate(idp_cert_fingerprint, logger = nil)
      # get cert from response
      base64_cert = self.at_xpath("//ds:X509Certificate", Onelogin::NAMESPACES).content
      cert_text = Base64.decode64(base64_cert)
      cert = OpenSSL::X509::Certificate.new(cert_text)

      # check cert matches registered idp cert, unless we explicitly skip this check
      unless idp_cert_fingerprint == '*'
        fingerprint = Digest::SHA1.hexdigest(cert.to_der)
        expected_fingerprints = Array(idp_cert_fingerprint).map { |f| f.gsub(":", "").downcase }
        unless expected_fingerprints.include?(fingerprint)
          @validation_error = "Invalid fingerprint (expected one of [#{expected_fingerprints.join(', ')}], got #{fingerprint})"
          return false
        end
      end

      # Force encoding of the xml and the xml string for validation
      xml = to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML, encoding: "ISO-8859-1")

      # validate it!
      validate_doc(xml, SignedDocument.format_cert(cert))
    end

    def validate_doc(xml, pem)
      kmgr = nil
      ctx = nil
      result = false

      begin
        # set up the keymgr
        kmgr = XMLSecurity.xmlSecKeysMngrCreate
        raise "failed initializing key mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrInit(kmgr) < 0
        key = XMLSecurity.xmlSecOpenSSLAppKeyLoadMemory(pem, pem.length, :xmlSecKeyDataFormatPem, nil, nil, nil)
        raise "failed loading key" if key.null?
        raise "failed adding key to mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(kmgr, key) < 0

        # parse the xml
        doc = XMLSecurity.xmlSecParseMemory(xml, xml.length, 0)
        root = XMLSecurity.xmlDocGetRootElement(doc)

        XMLSecurity.register_xml_id_attribute(doc, root)

        # get the root node, and then find the signature
        node = XMLSecurity.xmlSecFindNode(root, "Signature", "http://www.w3.org/2000/09/xmldsig#")
        raise "Signature node not found" if node.null?

        # create the sig context
        ctx = XMLSecurity.xmlSecDSigCtxCreate(kmgr)
        raise "failed creating digital signature context" if ctx.null?

        XMLSecurity.disable_xslt_transforms!(ctx)
        XMLSecurity.disable_remote_references!(ctx)

        # verify!
        raise "failed verifying dsig" if XMLSecurity.xmlSecDSigCtxVerify(ctx, node) < 0
        result = ctx[:status] == :xmlSecDSigStatusSucceeded
        @validation_error = ctx[:status].to_s unless result
      rescue Exception => e
        @validation_error = e.message
      ensure
        XMLSecurity.xmlSecDSigCtxDestroy(ctx) if ctx
        XMLSecurity.xmlFreeDoc(doc) if doc
        XMLSecurity.xmlSecKeysMngrDestroy(kmgr) if kmgr
      end

      result
    end

    # replaces EncryptedData nodes with decrypted copies
    def decrypt!(settings)
      if settings.encryption_configured?
        xpath("//xenc:EncryptedData", Onelogin::NAMESPACES).each do |node|
          decrypted_xml = decrypt_node(settings, node.to_s)
          if decrypted_xml
            decrypted_doc = Nokogiri::XML(decrypted_xml)
            decrypted_node = decrypted_doc.root
            node.parent.next = decrypted_node
            node.parent.unlink
          end
        end
      end
      true
    end

    def decrypt_node(settings, xmlstr)
      settings.all_private_keys.each do |key|
        result = xmlsec_decrypt(xmlstr, key)
        if result
          if settings.key_success_callback?
            settings.on_key_success.call(key)
          end
          return result
        end
      end
      nil
    end

    def xmlsec_decrypt(xmlstr, private_key)
      kmgr = nil
      ctx = nil
      doc = nil
      result = nil
      begin
        kmgr = XMLSecurity.xmlSecKeysMngrCreate
        raise "Failed initializing key mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrInit(kmgr) < 0

        key = XMLSecurity.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
        raise "Failed loading key" if key.null?
        raise "Failed adding key to mgr" if XMLSecurity.xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(kmgr, key) < 0

        doc = XMLSecurity.xmlSecParseMemory(xmlstr, xmlstr.length, 0)
        raise "Failed to parse node" if doc.null?

        ctx = XMLSecurity.xmlSecEncCtxCreate(kmgr)
        raise "failed creating enc ctx" if ctx.null?

        node = XMLSecurity.xmlDocGetRootElement(doc)
        raise "failed decrypting" if XMLSecurity.xmlSecEncCtxDecrypt(ctx, node) < 0

        ptr = FFI::MemoryPointer.new(:pointer, 1)
        sizeptr = FFI::MemoryPointer.new(:pointer, 1)
        XMLSecurity.xmlDocDumpFormatMemory(doc, ptr, sizeptr, 0)
        strptr = ptr.read_pointer
        result = strptr.null? ? nil : strptr.read_string
      rescue Exception => e
        @logger.warn "Could not decrypt: #{e.message}" if @logger
      ensure
        XMLSecurity.xmlSecEncCtxDestroy(ctx) if ctx
        XMLSecurity.xmlFreeDoc(doc) if doc
        XMLSecurity.xmlSecKeysMngrDestroy(kmgr) if kmgr
      end
      result
    end
  end

  class SignatureFailure < RuntimeError; end

  def self.sign(reference_id, xml_string, private_key, certificate)
    doc = self.xmlParseMemory(xml_string, xml_string.size)
    raise SignatureFailure.new("could not parse XML document") if doc.null?

    canonicalization_method_id = self.xmlSecTransformExclC14NGetKlass
    sign_method_id = self.xmlSecOpenSSLTransformRsaSha1GetKlass

    sign_node = self.xmlSecTmplSignatureCreate(doc, canonicalization_method_id, sign_method_id, nil)

    raise SignatureFailure.new("failed to create signature template") if sign_node.null?
    root = self.xmlDocGetRootElement(doc)
    self.xmlAddChild(root, sign_node)

    XMLSecurity.register_xml_id_attribute(doc, root)

    ref_node = self.xmlSecTmplSignatureAddReference(sign_node, self.xmlSecOpenSSLTransformSha1GetKlass, nil, reference_id && "##{reference_id}", nil)
    raise SignatureFailure.new("failed to add a reference") if ref_node.null?

    envelope_result = self.xmlSecTmplReferenceAddTransform(ref_node, self.xmlSecTransformEnvelopedGetKlass)
    raise SignatureFailure.new("failed to add envelope transform to reference") if envelope_result.null?

    key_info_node = self.xmlSecTmplSignatureEnsureKeyInfo(sign_node, nil)
    raise SignatureFailure.new("failed to add key info") if key_info_node.null?

    digital_signature_context = self.xmlSecDSigCtxCreate(nil)
    raise SignatureFailure.new("failed to create signature context") if digital_signature_context.null?

    digital_signature_context[:signKey] = self.xmlSecOpenSSLAppKeyLoad(private_key, :xmlSecKeyDataFormatPem, nil, nil, nil)
    raise SignatureFailure.new("failed to load private pem key from #{private_key}") if digital_signature_context[:signKey].null?

    if self.xmlSecOpenSSLAppKeyCertLoad(digital_signature_context[:signKey], certificate, :xmlSecKeyDataFormatPem) < 0
      raise SignatureFailure.new("failed to load public cert from #{certificate}")
    end

    x509_data_node = self.xmlSecTmplKeyInfoAddX509Data(key_info_node)
    raise SignatureFailure.new("failed to add <dsig:X509Data/> node") if x509_data_node.null?

    if self.xmlSecDSigCtxSign(digital_signature_context, sign_node) < 0
      raise SignatureFailure.new("signature failed!")
    end

    ptr = FFI::MemoryPointer.new(:pointer, 1)
    sizeptr = FFI::MemoryPointer.new(:pointer, 1)
    self.xmlDocDumpFormatMemory(doc, ptr, sizeptr, 0)
    strptr = ptr.read_pointer

    return strptr.null? ? nil : strptr.read_string
  ensure
    ptr.free if defined?(ptr) && ptr
    sizeptr.free if defined?(sizeptr) && sizeptr
    self.xmlFreeDoc(doc) if defined?(doc) && doc && !doc.null?
    self.xmlSecDSigCtxDestroy(digital_signature_context) if defined?(digital_signature_context) && digital_signature_context && !digital_signature_context.null?
    self.xmlFree(strptr) if defined?(strptr) && strptr && !strptr.null?
  end


  #
  # Register 'ID' as an XML id attribute so we can properly sign/validate
  # signatures with references of the form:
  #
  #   <dsig:Reference URI="#IdOfElementImSigning" />
  #
  # Which refer to another element in the same document like:
  #
  #   <elem ID="IdOfElementImSigning" />
  #
  # For more information see:
  #
  #   http://www.aleksey.com/xmlsec/faq.html#section_3_4
  #
  def self.register_xml_id_attribute(doc, root)
    idary = FFI::MemoryPointer.new(:pointer, 2)
    idary[0].put_pointer(0, FFI::MemoryPointer.from_string("ID"))
    idary[1].put_pointer(0, nil)
    XMLSecurity.xmlSecAddIDs(doc, root, idary)
  end
end
