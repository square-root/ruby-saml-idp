# encoding: utf-8

module SamlIdp
  module Controller
    require 'openssl'
    require 'base64'
    require 'time'
    require 'uuid'
    require 'xmldsig'

    attr_accessor :x509_certificate, :secret_key, :algorithm
    attr_accessor :saml_acs_url

    def x509_certificate
      return @x509_certificate if defined?(@x509_certificate)
      @x509_certificate = SamlIdp.config.x509_certificate
      if @x509_certificate =~ /-----BEGIN CERTIFICATE-----/
        @x509_certificate = OpenSSL::X509::Certificate.new(@x509_certificate)
      else
        @x509_certificate = OpenSSL::X509::Certificate.new(Base64.decode64(@x509_certificate))
      end
    end

    def x509_certificate_text
      Base64.encode64(x509_certificate.to_der).gsub("\n", '')
    end

    def secret_key
      return @secret_key if defined?(@secret_key)
      @secret_key = SamlIdp.config.secret_key
    end

    def algorithm
      return @algorithm if defined?(@algorithm)
      self.algorithm = SamlIdp.config.algorithm
      @algorithm
    end

    def algorithm=(algorithm)
      @algorithm = algorithm
      if algorithm.is_a?(Symbol)
        @algorithm = case algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        else
          OpenSSL::Digest::SHA1
        end
      end
      @algorithm
    end

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end

    def digest_method_url
      if algorithm_name == 'sha1'
        "http://www.w3.org/2000/09/xmldsig#sha1"
      else
        "http://www.w3.org/2001/04/xmlenc##{algorithm_name}"
      end
    end

    def signature_method_url
      if algorithm_name == 'sha1'
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
      else
        "http://www.w3.org/2001/04/xmldsig-more#rsa-#{algorithm_name}"
      end
    end

    protected

      def validate_saml_request(saml_request = params[:SAMLRequest])
        decode_SAMLRequest(saml_request)
      end

      def decode_SAMLRequest(saml_request)
        zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        @saml_request = zstream.inflate(Base64.decode64(saml_request))
        zstream.finish
        zstream.close
        @saml_request_id = @saml_request[/ID=['"](.+?)['"]/, 1]
        @saml_acs_url = @saml_request[/AssertionConsumerServiceURL=['"](.+?)['"]/, 1]
      end

      def encode_SAMLResponse(nameID, opts = {})
        now = Time.now.utc
        response_id, reference_id = UUID.generate, UUID.generate
        audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
        issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url) || "http://example.com"
        recipient_uri = opts[:recipient_uri] || @saml_acs_url || audience_uri
        include_xml_tag = opts[:include_xml_tag] || false
		attributes_statement = attributes(opts[:attributes_provider], nameID)

        assertion = %[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><saml:Issuer>#{issuer_uri}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">#{nameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="#{@saml_request_id}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{recipient_uri}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><saml:AudienceRestriction><saml:Audience>#{audience_uri}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>#{nameID}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>]
        digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')

        signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="#{signature_method_url}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ds:InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="#default samlp saml ds xs xsi" ></ds:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="#{digest_method_url}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]
        signature_value = sign(signed_info).gsub(/\n/, '')

        signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue></ds:SignatureValue><ds:KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate_text}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>]
        assertion_and_signature = assertion.sub(/Issuer\>\<saml:Subject/, "Issuer>#{signature}<saml:Subject")

        # Just display the xml tag if we require it
        xml = include_xml_tag ? '<?xml version="1.0" encoding="UTF-8"?>' : ''
        xml += %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{audience_uri}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

        # Sign the document using XMLdsig in order to be sure that everthing is as expected
        document = Xmldsig::SignedDocument.new(xml)
        final_doc = document.sign(OpenSSL::PKey::RSA.new(secret_key), false).gsub(/^\s+/, '').gsub(/\s+$/, '').gsub(/\n/, '')
        Base64.encode64(final_doc)
      end

    private
      def sign(data)
        key = OpenSSL::PKey::RSA.new(self.secret_key)
        Base64.encode64(key.sign(algorithm.new, data))
      end

      def attributes(provider, nameID)
        provider ? provider : %[<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>#{nameID}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]
      end
  end
end