#lang racket/base
(require racket/match
         asn1 asn1/util/names
         crypto/private/common/asn1
         (only-in crypto/private/common/catalog digest-security-bits)
         "interfaces.rkt")
(provide (all-defined-out)
         relation-ref)

;; Util:
(define TeletexString  (TAG #:implicit #:universal 20 OCTET-STRING))

;; ============================================================

(define-asn1-type Certificate-for-verify-sig
  (SEQUENCE
   (tbsCertificate ANY/DER)
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)))

(define-asn1-type CertificateList-for-verify-sig
  (SEQUENCE
   (tbsCertList ANY/DER)
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)))

;; ============================================================

;; ----------------------------------------
;; Attributes

(define id-at (OID (joint-iso-ccitt 2) (ds 5) 4))
(define id-at-name (build-OID id-at 41))
(define id-at-surname (build-OID id-at 4))
(define id-at-givenName (build-OID id-at 42))
(define id-at-initials (build-OID id-at 43))
(define id-at-generationQualifier (build-OID id-at 44))
(define id-at-commonName (build-OID id-at 3))
(define id-at-localityName (build-OID id-at 7))
(define id-at-stateOrProvinceName (build-OID id-at 8))
(define id-at-organizationName (build-OID id-at 10))
(define id-at-organizationalUnitName (build-OID id-at 11))
(define id-at-title (build-OID id-at 12))
(define id-at-dnQualifier (build-OID id-at 46))
(define id-at-countryName (build-OID id-at 6))
(define id-at-serialNumber (build-OID id-at 5))
(define id-at-pseudonym (build-OID id-at 65))
(define id-domainComponent (OID 0 9 2342 19200300 100 1 25))
(define pkcs-9 (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549) (pkcs 1) 9))
(define id-emailAddress (build-OID pkcs-9 1))

(define -SomeString
  (CHOICE
   (teletexString TeletexString)
   (printableString PrintableString)
   (universalString UniversalString)
   (utf8String UTF8String)
   (bmpString BMPString)))
(define X520name -SomeString)
(define X520CommonName -SomeString)
(define X520LocalityName -SomeString)
(define X520StateOrProvinceName -SomeString)
(define X520OrganizationName -SomeString)
(define X520OrganizationalUnitName -SomeString)
(define X520Title -SomeString)
(define X520Pseudonym -SomeString)
(define DirectoryString -SomeString)
(define X520dnQualifier PrintableString)
(define X520countryName PrintableString)
(define X520SerialNumber PrintableString)
(define DomainComponent IA5String)
(define EmailAddress IA5String)

(define ATTRIBUTES
  (relation
   #:heading
   ['oid                         'type]
   #:tuples
   [id-at-name                   X520name]
   [id-at-surname                X520name]
   [id-at-givenName              X520name]
   [id-at-initials               X520name]
   [id-at-generationQualifier    X520name]
   [id-at-commonName             X520CommonName]
   [id-at-localityName           X520LocalityName]
   [id-at-stateOrProvinceName    X520StateOrProvinceName]
   [id-at-organizationName       X520OrganizationName]
   [id-at-organizationalUnitName X520OrganizationalUnitName]
   [id-at-title                  X520Title]
   [id-at-dnQualifier            X520dnQualifier]
   [id-at-countryName            X520countryName]
   [id-at-serialNumber           X520SerialNumber]
   [id-at-pseudonym              X520Pseudonym]
   [id-domainComponent           DomainComponent]
   ;; Legacy attributes
   [id-emailAddress              EmailAddress]))

(define AttributeType OBJECT-IDENTIFIER)
(define (AttributeValue attr-oid)
  (or (relation-ref ATTRIBUTES 'oid attr-oid 'type) ANY))

(define Attribute
  (SEQUENCE
   (type AttributeType)
   (values #:dependent (SET-OF (AttributeValue type)))))
(define AttributeTypeAndValue
  (SEQUENCE
   (type AttributeType)
   (value #:dependent (AttributeValue type))))

;; ----------------------------------------
;; Names

(define RelativeDistinguishedName (SET-OF AttributeTypeAndValue))
(define RDNSequence (SEQUENCE-OF RelativeDistinguishedName))
(define DistinguishedName RDNSequence)
(define Name (CHOICE (rdnSequence RDNSequence)))

;; ----------------------------------------
;; Certificate

(define-asn1-type Certificate
  (SEQUENCE
   (tbsCertificate TBSCertificate)
   (signatureAlgorithm AlgorithmIdentifier/DER)
   (signature BIT-STRING)))

(define-asn1-type TBSCertificate
  (SEQUENCE
   (version #:explicit 0 Version #:default v1)
   (serialNumber CertificateSerialNumber)
   (signature AlgorithmIdentifier/DER)
   (issuer Name)
   (validity Validity)
   (subject Name)
   (subjectPublicKeyInfo SubjectPublicKeyInfo/DER)
   (issuerUniqueID #:implicit 1 UniqueIdentifier #:optional)
   (subjectUniqueID #:implicit 2 UniqueIdentifier #:optional)
   (extensions #:explicit 3 Extensions #:optional)))

(define Version INTEGER)
(define v1 0)
(define v2 1)
(define v3 2)

(define CertificateSerialNumber INTEGER)
(define Time (CHOICE (utcTime UTCTime) (generalTime GeneralizedTime)))
(define Validity (SEQUENCE (notBefore Time) (notAfter Time)))
(define UniqueIdentifier BIT-STRING)

(define SubjectPublicKeyInfo/DER ANY/DER)

(define Extension
  (SEQUENCE
   (extnID OBJECT-IDENTIFIER)
   (critical BOOLEAN #:default #f)
   (extnValue #:dependent (OCTET-STRING-containing
                           (relation-ref EXTENSIONS 'oid extnID 'type)))))

(define Extensions (SEQUENCE-OF Extension))

;; ----------------------------------------
;; CRLs

(define-asn1-type CertificateList
  (SEQUENCE
   (tbsCertList TBSCertList)
   (signatureAlgorithm AlgorithmIdentifier/DER)
   (signature BIT-STRING)))

(define-asn1-type TBSCertList
  (SEQUENCE
   (version Version #:optional)
   (signature AlgorithmIdentifier/DER)
   (issuer Name)
   (thisUpdate Time)
   (nextUpdate Time #:optional)
   (revokedCertificates
    (SEQUENCE-OF
     (SEQUENCE
      (userCertificate CertificateSerialNumber)
      (revocationDate Time)
      (crlEntryExtensions Extensions #:optional)))
    #:optional)
   (crlExtensions #:explicit 0 Extensions #:optional)))

;; ------------------------------------------------------------
;; Translation of PKIX1Explicit88

(define id-pkix
  (OID
   (iso 1)
   (identified-organization 3)
   (dod 6)
   (internet 1)
   (security 5)
   (mechanisms 5)
   (pkix 7)))
(define id-pe (build-OID id-pkix 1))
(define id-qt (build-OID id-pkix 2))
(define id-kp (build-OID id-pkix 3))
(define id-ad (build-OID id-pkix 48))
(define id-qt-cps (build-OID id-qt 1))
(define id-qt-unotice (build-OID id-qt 2))
(define id-ad-ocsp (build-OID id-ad 1))
(define id-ad-caIssuers (build-OID id-ad 2))
(define id-ad-timeStamping (build-OID id-ad 3))
(define id-ad-caRepository (build-OID id-ad 5))

(define common-name 1)
(define teletex-common-name 2)
(define teletex-organization-name 3)
(define teletex-personal-name 4)
(define teletex-organizational-unit-names 5)
(define pds-name 7)
(define physical-delivery-country-name 8)
(define postal-code 9)
(define physical-delivery-office-name 10)
(define physical-delivery-office-number 11)
(define extension-OR-address-components 12)
(define physical-delivery-personal-name 13)
(define physical-delivery-organization-name 14)
(define extension-physical-delivery-address-components 15)
(define unformatted-postal-address 16)
(define street-address 17)
(define post-office-box-address 18)
(define poste-restante-address 19)
(define unique-postal-name 20)
(define local-postal-attributes 21)
(define extended-network-address 22)
(define terminal-type 23)
(define teletex-domain-defined-attributes 6)

(define-asn1-type ORAddress
  (SEQUENCE
   (built-in-standard-attributes BuiltInStandardAttributes)
   (built-in-domain-defined-attributes BuiltInDomainDefinedAttributes #:optional)
   (extension-attributes ExtensionAttributes #:optional)))

(define-asn1-type BuiltInStandardAttributes
  (SEQUENCE
   (country-name CountryName #:optional)
   (administration-domain-name AdministrationDomainName #:optional)
   (network-address #:implicit 0 NetworkAddress #:optional)
   (terminal-identifier #:implicit 1 TerminalIdentifier #:optional)
   (private-domain-name #:explicit 2 PrivateDomainName #:optional)
   (organization-name #:implicit 3 OrganizationName #:optional)
   (numeric-user-identifier #:implicit 4 NumericUserIdentifier #:optional)
   (personal-name #:implicit 5 PersonalName #:optional)
   (organizational-unit-names #:implicit 6 OrganizationalUnitNames #:optional)))

(define CountryName
  (TAG #:explicit #:application 1
       (CHOICE
        (x121-dcc-code NumericString)
        (iso-3166-alpha2-code PrintableString))))
(define AdministrationDomainName
  (TAG #:explicit #:application 2
       (CHOICE
        (numeric NumericString)
        (printable PrintableString))))
(define-asn1-type NetworkAddress X121Address)
(define X121Address NumericString)
(define TerminalIdentifier PrintableString)
(define PrivateDomainName
  (CHOICE (numeric NumericString) (printable PrintableString)))
(define OrganizationName PrintableString)
(define NumericUserIdentifier NumericString)
(define PersonalName
  (SET
   (surname #:implicit 0 PrintableString)
   (given-name #:implicit 1 PrintableString #:optional)
   (initials #:implicit 2 PrintableString #:optional)
   (generation-qualifier #:implicit 3 PrintableString #:optional)))

(define-asn1-type OrganizationalUnitNames (SEQUENCE-OF OrganizationalUnitName))
(define OrganizationalUnitName PrintableString)

(define-asn1-type BuiltInDomainDefinedAttributes (SEQUENCE-OF BuiltInDomainDefinedAttribute))
(define BuiltInDomainDefinedAttribute
  (SEQUENCE (type PrintableString) (value PrintableString)))

(define-asn1-type ExtensionAttributes (SET-OF ExtensionAttribute))
(define-asn1-type ExtensionAttribute
  (SEQUENCE
   (extension-attribute-type #:implicit 0 INTEGER)
   (extension-attribute-value
    #:explicit 1 (begin ANY #| DEFINED BY extension-attribute-type |#))))

(define CommonName PrintableString)
(define TeletexCommonName TeletexString)
(define TeletexOrganizationName TeletexString)
(define TeletexPersonalName
  (SET
   (surname #:implicit 0 TeletexString)
   (given-name #:implicit 1 TeletexString #:optional)
   (initials #:implicit 2 TeletexString #:optional)
   (generation-qualifier #:implicit 3 TeletexString #:optional)))
(define-asn1-type TeletexOrganizationalUnitNames (SEQUENCE-OF TeletexOrganizationalUnitName))
(define TeletexOrganizationalUnitName TeletexString)
(define PDSName PrintableString)
(define PhysicalDeliveryCountryName
  (CHOICE (x121-dcc-code NumericString) (iso-3166-alpha2-code PrintableString)))
(define PostalCode
  (CHOICE (numeric-code NumericString) (printable-code PrintableString)))
(define-asn1-type PhysicalDeliveryOfficeName PDSParameter)
(define-asn1-type PhysicalDeliveryOfficeNumber PDSParameter)
(define-asn1-type ExtensionORAddressComponents PDSParameter)
(define-asn1-type PhysicalDeliveryPersonalName PDSParameter)
(define-asn1-type PhysicalDeliveryOrganizationName PDSParameter)
(define-asn1-type ExtensionPhysicalDeliveryAddressComponents PDSParameter)
(define-asn1-type UnformattedPostalAddress
  (SET
   (printable-address (SEQUENCE-OF PrintableString) #:optional)
   (teletex-string TeletexString #:optional)))
(define-asn1-type StreetAddress PDSParameter)
(define-asn1-type PostOfficeBoxAddress PDSParameter)
(define-asn1-type PosteRestanteAddress PDSParameter)
(define-asn1-type UniquePostalName PDSParameter)
(define-asn1-type LocalPostalAttributes PDSParameter)
(define-asn1-type PDSParameter
  (SET
   (printable-string PrintableString #:optional)
   (teletex-string TeletexString #:optional)))
(define-asn1-type ExtendedNetworkAddress
  (CHOICE
   (e163-4-address
    (SEQUENCE
     (number #:implicit 0 NumericString)
     (sub-address #:implicit 1 NumericString #:optional)))
   (psap-address #:implicit 0 PresentationAddress)))
(define-asn1-type PresentationAddress
  (SEQUENCE
   (pSelector #:explicit 0 OCTET-STRING #:optional)
   (sSelector #:explicit 1 OCTET-STRING #:optional)
   (tSelector #:explicit 2 OCTET-STRING #:optional)
   (nAddresses #:explicit 3 (SET-OF OCTET-STRING))))
(define-asn1-type TerminalType INTEGER)
(define-asn1-type TeletexDomainDefinedAttributes (SEQUENCE-OF TeletexDomainDefinedAttribute))
(define-asn1-type TeletexDomainDefinedAttribute
  (SEQUENCE (type TeletexString) (value TeletexString)))

;; ------------------------------------------------------------
;; Translation of PKIX1Implicit88

;; Value, etc definitions
(define id-ce (OID (joint-iso-ccitt 2) (ds 5) 29))
(define id-ce-authorityKeyIdentifier (build-OID id-ce 35))
(define id-ce-subjectKeyIdentifier (build-OID id-ce 14))
(define id-ce-keyUsage (build-OID id-ce 15))
(define id-ce-privateKeyUsagePeriod (build-OID id-ce 16))
(define id-ce-certificatePolicies (build-OID id-ce 32))
(define anyPolicy (build-OID id-ce-certificatePolicies 0))
(define id-ce-policyMappings (build-OID id-ce 33))
(define id-ce-subjectAltName (build-OID id-ce 17))
(define id-ce-issuerAltName (build-OID id-ce 18))
(define id-ce-subjectDirectoryAttributes (build-OID id-ce 9))
(define id-ce-basicConstraints (build-OID id-ce 19))
(define id-ce-nameConstraints (build-OID id-ce 30))
(define id-ce-policyConstraints (build-OID id-ce 36))
(define id-ce-cRLDistributionPoints (build-OID id-ce 31))
(define id-ce-extKeyUsage (build-OID id-ce 37))
(define anyExtendedKeyUsage (build-OID id-ce-extKeyUsage 0))
(define id-kp-serverAuth (build-OID id-kp 1))
(define id-kp-clientAuth (build-OID id-kp 2))
(define id-kp-codeSigning (build-OID id-kp 3))
(define id-kp-emailProtection (build-OID id-kp 4))
(define id-kp-timeStamping (build-OID id-kp 8))
(define id-kp-OCSPSigning (build-OID id-kp 9))
(define id-ce-inhibitAnyPolicy (build-OID id-ce 54))
(define id-ce-freshestCRL (build-OID id-ce 46))
(define id-pe-authorityInfoAccess (build-OID id-pe 1))
(define id-pe-subjectInfoAccess (build-OID id-pe 11))
(define id-ce-cRLNumber (build-OID id-ce 20))
(define id-ce-issuingDistributionPoint (build-OID id-ce 28))
(define id-ce-deltaCRLIndicator (build-OID id-ce 27))
(define id-ce-cRLReasons (build-OID id-ce 21))
(define id-ce-certificateIssuer (build-OID id-ce 29))
(define id-ce-holdInstructionCode (build-OID id-ce 23))
(define holdInstruction (OID (joint-iso-itu-t 2) (member-body 2) (us 840) (x9cm 10040) 2))
(define id-holdinstruction-none (build-OID holdInstruction 1))
(define id-holdinstruction-callissuer (build-OID holdInstruction 2))
(define id-holdinstruction-reject (build-OID holdInstruction 3))
(define id-ce-invalidityDate (build-OID id-ce 24))

;; Type definitions
(define-asn1-type AuthorityKeyIdentifier
  (SEQUENCE
   (keyIdentifier #:implicit 0 KeyIdentifier #:optional)
   (authorityCertIssuer #:implicit 1 GeneralNames #:optional)
   (authorityCertSerialNumber #:implicit 2 CertificateSerialNumber #:optional)))
(define-asn1-type KeyIdentifier OCTET-STRING)
(define-asn1-type SubjectKeyIdentifier KeyIdentifier)

(define KeyUsage
  (WRAP-NAMES BIT-STRING
   (list
    (cons 'digitalSignature 0)
    (cons 'nonRepudiation 1)
    (cons 'keyEncipherment 2)
    (cons 'dataEncipherment 3)
    (cons 'keyAgreement 4)
    (cons 'keyCertSign 5)
    (cons 'cRLSign 6)
    (cons 'encipherOnly 7)
    (cons 'decipherOnly 8))))

(define PrivateKeyUsagePeriod
  (SEQUENCE
   (notBefore #:implicit 0 GeneralizedTime #:optional)
   (notAfter #:implicit 1 GeneralizedTime #:optional)))

(define-asn1-type CertificatePolicies (SEQUENCE-OF PolicyInformation))
(define-asn1-type PolicyInformation
  (SEQUENCE
   (policyIdentifier CertPolicyId)
   (policyQualifiers (SEQUENCE-OF PolicyQualifierInfo) #:optional)))
(define-asn1-type CertPolicyId OBJECT-IDENTIFIER)
(define-asn1-type PolicyQualifierInfo
  (SEQUENCE
   (policyQualifierId PolicyQualifierId)
   (qualifier #:dependent (relation-ref POLICY-QUALIFIERS 'oid policyQualifierId 'type))))
(define-asn1-type PolicyQualifierId OBJECT-IDENTIFIER)

(define CPSuri IA5String)

(define-asn1-type UserNotice
  (SEQUENCE (noticeRef NoticeReference #:optional) (explicitText DisplayText #:optional)))
(define-asn1-type NoticeReference
  (SEQUENCE (organization DisplayText) (noticeNumbers (SEQUENCE-OF INTEGER))))
(define-asn1-type DisplayText
  (CHOICE
   (ia5String IA5String)
   (visibleString VisibleString)
   (bmpString BMPString)
   (utf8String UTF8String)))

(define-asn1-type PolicyMappings
  (SEQUENCE-OF
   (SEQUENCE (issuerDomainPolicy CertPolicyId) (subjectDomainPolicy CertPolicyId))))

(define-asn1-type SubjectAltName GeneralNames)
(define-asn1-type GeneralNames (SEQUENCE-OF GeneralName))
(define-asn1-type GeneralName
  (CHOICE
   (otherName #:implicit 0 AnotherName)
   (rfc822Name #:implicit 1 IA5String)
   (dNSName #:implicit 2 IA5String)
   (x400Address #:implicit 3 ORAddress)
   (directoryName #:explicit 4 Name)
   (ediPartyName #:implicit 5 EDIPartyName)
   (uniformResourceIdentifier #:implicit 6 IA5String)
   (iPAddress #:implicit 7 OCTET-STRING)
   (registeredID #:implicit 8 OBJECT-IDENTIFIER)))
(define-asn1-type AnotherName
  (SEQUENCE
   (type-id OBJECT-IDENTIFIER)
   (value #:explicit 0 (begin ANY #| DEFINED BY type-id |#))))
(define-asn1-type EDIPartyName
  (SEQUENCE
   (nameAssigner #:explicit 0 DirectoryString #:optional)
   (partyName #:explicit 1 DirectoryString)))

(define-asn1-type IssuerAltName GeneralNames)
(define-asn1-type SubjectDirectoryAttributes (SEQUENCE-OF Attribute))
(define-asn1-type BasicConstraints
  (SEQUENCE (cA BOOLEAN #:default #f) (pathLenConstraint INTEGER #:optional)))
(define-asn1-type NameConstraints
  (SEQUENCE
   (permittedSubtrees #:implicit 0 GeneralSubtrees #:optional)
   (excludedSubtrees #:implicit 1 GeneralSubtrees #:optional)))
(define-asn1-type GeneralSubtrees (SEQUENCE-OF GeneralSubtree))
(define-asn1-type GeneralSubtree
  (SEQUENCE
   (base GeneralName)
   (minimum #:implicit 0 BaseDistance #:default 0)
   (maximum #:implicit 1 BaseDistance #:optional)))
(define-asn1-type BaseDistance INTEGER)
(define-asn1-type PolicyConstraints
  (SEQUENCE
   (requireExplicitPolicy #:implicit 0 SkipCerts #:optional)
   (inhibitPolicyMapping #:implicit 1 SkipCerts #:optional)))
(define-asn1-type SkipCerts INTEGER)
(define-asn1-type CRLDistributionPoints (SEQUENCE-OF DistributionPoint))
(define-asn1-type DistributionPoint
  (SEQUENCE
   (distributionPoint #:explicit 0 DistributionPointName #:optional)
   (reasons #:implicit 1 ReasonFlags #:optional)
   (cRLIssuer #:implicit 2 GeneralNames #:optional)))
(define-asn1-type DistributionPointName
  (CHOICE
   (fullName #:implicit 0 GeneralNames)
   (nameRelativeToCRLIssuer #:implicit 1 RelativeDistinguishedName)))
(define-asn1-type ReasonFlags
  (WRAP-NAMES BIT-STRING
   (list
    (cons 'unused 0)
    (cons 'keyCompromise 1)
    (cons 'cACompromise 2)
    (cons 'affiliationChanged 3)
    (cons 'superseded 4)
    (cons 'cessationOfOperation 5)
    (cons 'certificateHold 6)
    (cons 'privilegeWithdrawn 7)
    (cons 'aACompromise 8))))
(define-asn1-type ExtKeyUsageSyntax (SEQUENCE-OF KeyPurposeId))
(define-asn1-type KeyPurposeId OBJECT-IDENTIFIER)
(define-asn1-type InhibitAnyPolicy SkipCerts)
(define-asn1-type FreshestCRL CRLDistributionPoints)
(define-asn1-type AuthorityInfoAccessSyntax (SEQUENCE-OF AccessDescription))
(define-asn1-type AccessDescription
  (SEQUENCE (accessMethod OBJECT-IDENTIFIER) (accessLocation GeneralName)))
(define-asn1-type SubjectInfoAccessSyntax (SEQUENCE-OF AccessDescription))
(define-asn1-type CRLNumber INTEGER)
(define-asn1-type IssuingDistributionPoint
  (SEQUENCE
   (distributionPoint #:explicit 0 DistributionPointName #:optional)
   (onlyContainsUserCerts #:implicit 1 BOOLEAN #:default #f)
   (onlyContainsCACerts #:implicit 2 BOOLEAN #:default #f)
   (onlySomeReasons #:implicit 3 ReasonFlags #:optional)
   (indirectCRL #:implicit 4 BOOLEAN #:default #f)
   (onlyContainsAttributeCerts #:implicit 5 BOOLEAN #:default #f)))
(define-asn1-type BaseCRLNumber CRLNumber)
(define-asn1-type CRLReason
  (WRAP-NAMES ENUMERATED
   (list
    (cons 'unspecified 0)
    (cons 'keyCompromise 1)
    (cons 'cACompromise 2)
    (cons 'affiliationChanged 3)
    (cons 'superseded 4)
    (cons 'cessationOfOperation 5)
    (cons 'certificateHold 6)
    (cons 'removeFromCRL 8)
    (cons 'privilegeWithdrawn 9)
    (cons 'aACompromise 10))))
(define-asn1-type CertificateIssuer GeneralNames)
(define-asn1-type HoldInstructionCode OBJECT-IDENTIFIER)
(define-asn1-type InvalidityDate GeneralizedTime)

;; ------------------------------------------------------------
;; RFC 6960 (PKIX OCSP)

(define id-pkix-ocsp id-ad-ocsp)
(define id-pkix-ocsp-nocheck (build-OID id-pkix-ocsp 5))

;; ============================================================

(define EXTENSIONS
  (relation
   #:heading
   ['oid                              'type]
   #:tuples
   [id-ce-authorityKeyIdentifier      AuthorityKeyIdentifier]
   [id-ce-subjectKeyIdentifier        SubjectKeyIdentifier]
   [id-ce-keyUsage                    KeyUsage]
   [id-ce-certificatePolicies         CertificatePolicies]
   [id-ce-policyMappings              PolicyMappings]
   [id-ce-subjectAltName              SubjectAltName]
   [id-ce-issuerAltName               IssuerAltName]
   [id-ce-subjectDirectoryAttributes  SubjectDirectoryAttributes]
   [id-ce-basicConstraints            BasicConstraints]
   [id-ce-nameConstraints             NameConstraints]
   [id-ce-policyConstraints           PolicyConstraints]
   [id-ce-extKeyUsage                 ExtKeyUsageSyntax]
   [id-ce-cRLDistributionPoints       CRLDistributionPoints]
   [id-ce-inhibitAnyPolicy            InhibitAnyPolicy]
   [id-ce-freshestCRL                 CRLDistributionPoints]
   [id-pe-authorityInfoAccess         AuthorityInfoAccessSyntax]
   [id-pe-subjectInfoAccess           SubjectInfoAccessSyntax]
   ;; for CRLs only
   [id-ce-cRLNumber                   CRLNumber]
   [id-ce-deltaCRLIndicator           CRLNumber]
   [id-ce-issuingDistributionPoint    IssuingDistributionPoint]
   [id-ce-freshestCRL                 FreshestCRL]
   [id-ce-cRLReasons                  CRLReason]
   [id-ce-invalidityDate              InvalidityDate]
   [id-ce-certificateIssuer           CertificateIssuer]
   ))

(define POLICY-QUALIFIERS
  (relation
   #:heading
   ['oid            'type]
   #:tuples
   [id-qt-cps       CPSuri]
   [id-qt-unotice   UserNotice]))

(define SIGNING
  (relation
   #:heading
   ['oid                    'pk  'digest 'params  'params-presence]
   #:tuples
   ;; From RFC 5912:
   [md5WithRSAEncryption    'rsa 'md5    NULL     'required]
   [sha1WithRSAEncryption   'rsa 'sha1   NULL     'required]
   [sha224WithRSAEncryption 'rsa 'sha224 NULL     'required]
   [sha256WithRSAEncryption 'rsa 'sha256 NULL     'required]
   [sha384WithRSAEncryption 'rsa 'sha384 NULL     'required]
   [sha512WithRSAEncryption 'rsa 'sha512 NULL     'required]
   [id-RSASSA-PSS           'rsa #f      RSASSA-PSS-params 'required]
   [dsa-with-sha1           'dsa 'sha1   NULL     'absent]
   [id-dsa-with-sha224      'dsa 'sha224 NULL     'absent]
   [id-dsa-with-sha256      'dsa 'sha256 NULL     'absent]
   [id-dsa-with-sha384      'dsa 'sha384 NULL     'absent]
   [id-dsa-with-sha512      'dsa 'sha512 NULL     'absent]
   [ecdsa-with-SHA1         'ec  'sha1   NULL     'absent]
   [ecdsa-with-SHA224       'ec  'sha224 NULL     'absent]
   [ecdsa-with-SHA256       'ec  'sha256 NULL     'absent]
   [ecdsa-with-SHA384       'ec  'sha384 NULL     'absent]
   [ecdsa-with-SHA512       'ec  'sha512 NULL     'absent]

   ;; From RFC 8410:
   [id-Ed25519              'eddsa #f    #f       'absent]
   [id-Ed448                'eddsa #f    #f       'absent]
   ))

(define (pss-with-digest? alg hash-oid hash-length)
  (match alg
    [(hash-table ['hashAlgorithm (hash-table ['algorithm (== hash-oid)])]
                 ['maskGenAlgorithm
                  (hash-table ['algorithm (== id-mgf1)]
                              ['parameters (hash-table ['algorithm (== hash-oid)])])]
                 ['saltLength hash-length]
                 ['trailerField 1])
     #t]
    [else #f]))

;; sig-alg-security-bits : AlgorithmIdentifier -> Nat/#f
;; Returns the security bits for the *digest* used by the signature algorithm.
;; The public key strength is not considered. Returns #f when there is no separate
;; digest, 0 for unknown digest.
(define (sig-alg-security-bits alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (match (relation-ref* SIGNING 'oid alg-oid '(pk digest))
    [(list 'eddsa #f) #f]
    [(list 'rsa #f) ;; means RSA w/ PSS
     (define alg-params (hash-ref alg 'parameters))
     (define di
       (cond [(pss-with-digest? alg-params id-sha1 20) 'sha1]
             [(pss-with-digest? alg-params id-sha256 32) 'sha256]
             [(pss-with-digest? alg-params id-sha384 48) 'sha384]
             [(pss-with-digest? alg-params id-sha512 64) 'sha512]
             [else #f]))
     (if di (digest-security-bits di #t) 0)]
    [(list pk di)
     (digest-security-bits di #t)]
    [_ 0]))

(module+ verify
  (require racket/class
           racket/contract
           scramble/result
           crypto)
  (provide (contract-out
            [check-signature/algid
             (-> pk-key? (or/c bytes? asn1-algorithm-identifier/c) bytes? bytes?
                 (result/c #t (listof symbol?)))]
            [verify/algid
             (-> pk-key? (or/c bytes? asn1-algorithm-identifier/c) bytes? bytes?
                 boolean?)]))

  ;; check-signature/algid : PublicKey (U Bytes AlgorithmIdentifier) Bytes Bytes
  ;;                      -> (Result #t (Listof Symbol))
  (define (check-signature/algid pk algid tbs sig)
    (define alg (if (bytes? algid) (bytes->asn1 AlgorithmIdentifier algid) algid))
    (define alg-oid (hash-ref alg 'algorithm))
    (match (relation-ref* SIGNING 'oid alg-oid '(pk digest))
      [(list 'eddsa #f)
       (cond [(not (eq? 'eddsa (send pk get-spec))) (bad '(signature:key:wrong-type))]
             [(pk-verify pk tbs sig) (ok #t)]
             [else (bad '(signature:bad))])]
      [(list 'rsa #f) ;; means RSA w/ PSS
       (define alg-params (hash-ref alg 'parameters))
       (define di
         (cond [(pss-with-digest? alg-params id-sha1 20) 'sha1]
               [(pss-with-digest? alg-params id-sha256 32) 'sha256]
               [(pss-with-digest? alg-params id-sha384 48) 'sha384]
               [(pss-with-digest? alg-params id-sha512 64) 'sha512]
               [else #f]))
       (cond [(not (eq? 'rsa (send pk get-spec))) (bad '(signature:key:wrong-type))]
             [(not di) (bad '(signature:unknown-pss-digest))]
             [(not (pk-can-sign? pk 'pss di)) (bad '(signature:key:unsupported-padding/digest))]
             [(digest/verify pk di tbs sig #:pad 'pss) (ok #t)]
             [else (bad '(signature:bad))])]
      [(list pk-type di)
       (cond [(not (eq? pk-type (send pk get-spec))) (bad '(signature:key:wrong-type))]
             [(not (pk-can-sign? pk #f di)) (bad '(signature:key:unsupported-padding/digest))]
             [(digest/verify pk di tbs sig) (ok #t)]
             [else (bad '(signature:bad))])]
      [_ (bad '(signature:unknown-algorithm))]))

  ;; verify/algid : PublicKey AlgorithmIdentifier Bytes Bytes -> Boolean
  ;; If key is wrong type just return #f, no error.
  (define (verify/algid pk alg tbs sig)
    (ok? (check-signature/algid pk alg tbs sig))))
