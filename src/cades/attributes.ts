import {
  derExplicit,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  derUtcTime,
  derUtf8String,
} from '../asn1/der.js'
import {
  cmsAttribute,
  cmsDigest,
  digestAlgorithmIdentifier,
  type CmsDigest,
} from '../pki/cms-build.js'
import { certificateNames, serialNumberNode } from '../pki/extensions.js'

import { COMMITMENT_OID, SignedAttribute, type CadesCommitmentType } from './constants.js'

/**
 * CAdES imzalanmış öznitelikleri — ETSI TS 101 733 / EN 319 122.
 */

/** İmzalayanın yeri. */
export interface SignerLocation {
  readonly country?: string
  readonly locality?: string
  readonly postalAddress?: readonly string[]
}

/**
 * İmza politikası — CAdES-EPES.
 *
 * Özet, politika BELGESİNİN özetidir; kütüphane onu uyduramaz çünkü
 * belgeyi görmez. `'implied'` verilirse politika yalnızca ima edilir ve
 * özet gerekmez.
 */
export interface CadesSignaturePolicy {
  readonly oid: string
  readonly digest: { readonly algorithm: CmsDigest; readonly value: Uint8Array }
}

/** `contentType` özniteliği. */
export const contentTypeAttribute = (oid: string): Uint8Array =>
  cmsAttribute(SignedAttribute.CONTENT_TYPE, derOid(oid))

/** `messageDigest` özniteliği. */
export const messageDigestAttribute = (digest: Uint8Array): Uint8Array =>
  cmsAttribute(SignedAttribute.MESSAGE_DIGEST, derOctetString(digest))

/** `signingTime` özniteliği. */
export const signingTimeAttribute = (when: Date): Uint8Array =>
  cmsAttribute(SignedAttribute.SIGNING_TIME, derUtcTime(when))

/**
 * `signingCertificateV2` özniteliği — RFC 5035.
 *
 * **CAdES-BES'i CAdES-BES yapan öznitelik budur.** Sertifikanın özetini ve
 * düzenleyen/seri ikilisini imzaya bağlar; olmadan imza düz bir CMS
 * imzasıdır ve imzalayan sertifika sonradan değiştirilebilir.
 *
 * `hashAlgorithm` alanı SHA-256'da **yazılmaz**: ASN.1 tanımında
 * `DEFAULT id-sha256` ve DER varsayılan değerleri kodlamaz. Yazmak katı
 * bir doğrulayıcıda reddedilme sebebidir.
 */
export const signingCertificateAttribute = (
  certificate: Uint8Array,
  digest: CmsDigest,
): Uint8Array => {
  const names = certificateNames(certificate)
  const essCertId = derSequence(
    ...(digest === 'sha256' ? [] : [digestAlgorithmIdentifier(digest)]),
    derOctetString(cmsDigest(digest, certificate)),
    derSequence(
      // GeneralNames ::= SEQUENCE OF GeneralName; directoryName [4] EXPLICIT.
      derSequence(derExplicit(4, names.issuer)),
      serialNumberNode(certificate).raw,
    ),
  )
  return cmsAttribute(SignedAttribute.SIGNING_CERTIFICATE_V2, derSequence(derSequence(essCertId)))
}

/** `signaturePolicyIdentifier` özniteliği — EPES. */
export const signaturePolicyAttribute = (policy: CadesSignaturePolicy | 'implied'): Uint8Array =>
  policy === 'implied'
    ? cmsAttribute(SignedAttribute.SIGNATURE_POLICY_ID, derNull())
    : cmsAttribute(
        SignedAttribute.SIGNATURE_POLICY_ID,
        derSequence(
          derOid(policy.oid),
          derSequence(
            digestAlgorithmIdentifier(policy.digest.algorithm),
            derOctetString(policy.digest.value),
          ),
        ),
      )

/** `commitmentTypeIndication` özniteliği. */
export const commitmentTypeAttribute = (commitment: CadesCommitmentType): Uint8Array =>
  cmsAttribute(SignedAttribute.COMMITMENT_TYPE, derSequence(derOid(COMMITMENT_OID[commitment])))

/**
 * `signerLocation` özniteliği.
 *
 * ETSI TS 101 733'ün ASN.1 modülü `EXPLICIT TAGS` kullanır; alanlar bu
 * yüzden açık etiketli.
 */
export const signerLocationAttribute = (location: SignerLocation): Uint8Array =>
  cmsAttribute(
    SignedAttribute.SIGNER_LOCATION,
    derSequence(
      ...(location.country === undefined ? [] : [derExplicit(0, derUtf8String(location.country))]),
      ...(location.locality === undefined
        ? []
        : [derExplicit(1, derUtf8String(location.locality))]),
      ...(location.postalAddress === undefined || location.postalAddress.length === 0
        ? []
        : [
            derExplicit(
              2,
              derSequence(...location.postalAddress.map((line) => derUtf8String(line))),
            ),
          ]),
    ),
  )

/** Kodlanmış bir zaman damgası jetonunu imzalanmamış öznitelik olarak sarar. */
export const timestampAttribute = (oid: string, token: Uint8Array): Uint8Array =>
  cmsAttribute(oid, token)

/** Sertifika ve iptal verisi öznitelikleri — LT seviyesi. */
export const certificateValuesAttribute = (
  oid: string,
  certificates: readonly Uint8Array[],
): Uint8Array => cmsAttribute(oid, derSequence(...certificates))

/**
 * `revocationValues` özniteliği.
 *
 * ```text
 * RevocationValues ::= SEQUENCE {
 *   crlVals      [0] SEQUENCE OF CertificateList OPTIONAL,
 *   ocspVals     [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 *   otherRevVals [2] OtherRevVals OPTIONAL }
 * ```
 */
export const revocationValuesAttribute = (
  oid: string,
  crls: readonly Uint8Array[],
  ocspResponses: readonly Uint8Array[],
): Uint8Array =>
  cmsAttribute(
    oid,
    derSequence(
      ...(crls.length === 0 ? [] : [derExplicit(0, derSequence(...crls))]),
      ...(ocspResponses.length === 0 ? [] : [derExplicit(1, derSequence(...ocspResponses))]),
    ),
  )
