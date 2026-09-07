import { asOctetString, asOid, asSequence, asTime, type DerNode } from '../asn1/der.js'
import { timingSafeEqual } from '../core/bytes.js'
import { VerificationError } from '../core/errors.js'
import { readCertificate, type CertificateInfo } from '../pki/certificate.js'
import { cmsDigest, type CmsDigest } from '../pki/cms-build.js'
import {
  attributeValues,
  parseCmsSignedData,
  signedAttribute,
  verifyCmsSigner,
  type CmsSignerInfo,
} from '../pki/cms.js'
import { verifyTimestampToken } from '../pki/tsp.js'

import { SignedAttribute, UnsignedAttribute, type CadesLevel } from './constants.js'

/**
 * CAdES doğrulama.
 *
 * `valid: true` ne demek, ne demek değil sorusunun cevabı XAdES ile
 * aynıdır: yapısal ve kriptografik geçerlilik doğrulanır, sertifikanın
 * güvenilirliği ve iptal durumu **doğrulanmaz**. Ayrıntı için paketin
 * README'sindeki ilgili bölüm.
 */

/** Bir CAdES zaman damgasının doğrulama sonucu. */
export interface CadesTimestampResult {
  readonly kind: 'signature' | 'archive'
  readonly valid: boolean
  readonly genTime?: Date
  readonly policyOid?: string
  readonly reason?: string
}

/** Doğrulamayı geçersiz KILMAYAN gözlemler. */
export interface CadesWarning {
  readonly code:
    | 'no-signing-certificate-attribute'
    | 'signing-certificate-digest-mismatch'
    | 'certificate-expired-at-signing'
    | 'certificate-currently-expired'
    | 'timestamp-invalid'
  readonly message: string
}

/** {@link cadesVerify} sonucu. */
export type CadesVerification =
  | {
      readonly valid: true
      readonly level: CadesLevel
      readonly signer: CertificateInfo
      readonly signingTime?: Date
      /** Sarmalanan içeriğin türü. */
      readonly contentType: string
      /** İçerik yapıya gömülü mü. */
      readonly attached: boolean
      readonly timestamps: readonly CadesTimestampResult[]
      readonly warnings: readonly CadesWarning[]
    }
  | { readonly valid: false; readonly reason: string }

/** {@link cadesVerify} seçenekleri. */
export interface CadesVerifyOptions {
  /**
   * Ayrık imzada dışarıda tutulan veri.
   *
   * İmza ayrıksa bu **zorunludur**: veri olmadan `messageDigest` bağı
   * kurulamaz ve imzanın neyi kapsadığı bilinemez.
   */
  readonly content?: Uint8Array
}

/**
 * CAdES imzasını doğrular.
 *
 * @param cms - CMS `ContentInfo` DER kodlaması
 * @param options - {@link CadesVerifyOptions}
 * @returns Doğrulama sonucu; geçersizlik hata değil, sonuçtur
 * @throws {VerificationError} Yapı hiç okunamazsa
 */
export const cadesVerify = (
  cms: Uint8Array,
  options: CadesVerifyOptions = {},
): CadesVerification => {
  let signed
  try {
    signed = parseCmsSignedData(cms)
  } catch (error) {
    throw new VerificationError(
      `CMS yapısı okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  const signer = signed.signerInfos[0]
  if (signer === undefined) return { valid: false, reason: 'Yapıda imzacı yok.' }

  const attached = signed.content !== undefined
  if (!attached && options.content === undefined) {
    return {
      valid: false,
      reason:
        'İmza ayrık (detached) ve içerik verilmedi. ' +
        'Veri olmadan imzanın neyi kapsadığı bilinemez.',
    }
  }

  const outcome = verifyCmsSigner(signed, signer, options.content)
  if (!outcome.valid) return { valid: false, reason: outcome.reason }

  const certificate = readCertificate(outcome.certificate)
  const warnings: CadesWarning[] = []

  // ── CAdES-BES bağı ─────────────────────────────────────────────────────
  const binding = signingCertificateBinding(signer, outcome.certificate)
  if (binding === 'missing') {
    warnings.push({
      code: 'no-signing-certificate-attribute',
      message:
        'signingCertificate özniteliği yok — imza düz bir CMS imzası, CAdES-BES değil. ' +
        'İmzalayan sertifika imzaya bağlanmamış.',
    })
  } else if (binding === 'mismatch') {
    warnings.push({
      code: 'signing-certificate-digest-mismatch',
      message: 'signingCertificate özeti, imzayı doğrulayan sertifikayla eşleşmiyor.',
    })
  }

  // ── Zaman ──────────────────────────────────────────────────────────────
  const timeNode = signedAttribute(signer, SignedAttribute.SIGNING_TIME)
  let signingTime: Date | undefined
  if (timeNode !== undefined) {
    try {
      signingTime = asTime(timeNode)
    } catch {
      signingTime = undefined
    }
  }
  if (signingTime !== undefined && signingTime > certificate.notAfter) {
    warnings.push({
      code: 'certificate-expired-at-signing',
      message: `İmza zamanı (${signingTime.toISOString()}) sertifikanın geçerlilik bitişinden sonra.`,
    })
  }
  if (new Date() > certificate.notAfter) {
    warnings.push({
      code: 'certificate-currently-expired',
      message: `Sertifikanın geçerliliği ${certificate.notAfter.toISOString()} tarihinde dolmuş.`,
    })
  }

  // ── Zaman damgaları ────────────────────────────────────────────────────
  const timestamps = verifyCadesTimestamps(signer)
  for (const timestamp of timestamps) {
    if (!timestamp.valid) {
      warnings.push({
        code: 'timestamp-invalid',
        message: `Zaman damgası doğrulanamadı: ${timestamp.reason ?? 'bilinmeyen sebep'}`,
      })
    }
  }

  return {
    valid: true,
    level: detectCadesLevel(signer, binding, timestamps),
    signer: certificate,
    ...(signingTime === undefined ? {} : { signingTime }),
    contentType: signed.contentType,
    attached,
    timestamps,
    warnings,
  }
}

/** `signingCertificateV2` bağının durumu. */
type Binding = 'ok' | 'missing' | 'mismatch'

/**
 * `signingCertificate` özniteliğinin, imzayı doğrulayan sertifikayla
 * tutarlı olup olmadığını söyler.
 *
 * Bu bağ CAdES-BES'i düz CMS'ten ayıran şey: olmadan, imzayı doğrulayan
 * sertifika yapının içinde değiştirilebilir.
 */
const signingCertificateBinding = (signer: CmsSignerInfo, certificate: Uint8Array): Binding => {
  for (const [oid, defaultDigest] of [
    [SignedAttribute.SIGNING_CERTIFICATE_V2, 'sha256'],
    // v1 yalnızca OKUNUR; yazılmaz. Eski imzaları reddetmemek için burada.
    [SignedAttribute.SIGNING_CERTIFICATE_V1, 'sha1'],
  ] as const) {
    const value = signedAttribute(signer, oid)
    if (value === undefined) continue
    const certs = asSequence(asSequence(value)[0] ?? value)
    const essCertId = certs[0]
    if (essCertId === undefined) return 'mismatch'
    const fields = asSequence(essCertId)

    // `hashAlgorithm` DEFAULT id-sha256; yoksa varsayılan geçerli.
    const first = fields[0]
    let algorithm: string = defaultDigest
    let hashIndex = 0
    if (first?.tagNumber === 16 /* SEQUENCE */) {
      algorithm = digestNameFromOid(asOid(asSequence(first)[0] ?? first)) ?? defaultDigest
      hashIndex = 1
    }
    const hashNode = fields[hashIndex]
    if (hashNode === undefined) return 'mismatch'

    const expected = cmsDigest(algorithm as CmsDigest, certificate)
    return timingSafeEqual(expected, asOctetString(hashNode)) ? 'ok' : 'mismatch'
  }
  return 'missing'
}

/** Özet OID'ini `node:crypto` adına çevirir. */
const digestNameFromOid = (oid: string): string | undefined =>
  ({
    '1.3.14.3.2.26': 'sha1',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
  })[oid]

/**
 * İmzalanmamış özniteliklerdeki zaman damgalarını doğrular.
 *
 * ETSI TS 101 733 §6.1.1: imza zaman damgasının girdisi, `SignerInfo`
 * imza alanındaki **OCTET STRING'in DEĞERİDİR** — sarmalayıcı değil.
 */
const verifyCadesTimestamps = (signer: CmsSignerInfo): readonly CadesTimestampResult[] => {
  const results: CadesTimestampResult[] = []
  const check = (
    kind: 'signature' | 'archive',
    tokens: readonly DerNode[],
    data: Uint8Array | undefined,
  ): void => {
    for (const token of tokens) {
      const outcome = verifyTimestampToken(token.raw, data === undefined ? {} : { data })
      results.push(
        outcome.valid
          ? {
              kind,
              valid: true,
              genTime: outcome.info.genTime,
              policyOid: outcome.info.policyOid,
            }
          : { kind, valid: false, reason: outcome.reason },
      )
    }
  }

  check(
    'signature',
    attributeValues(signer.unsignedAttributes, UnsignedAttribute.SIGNATURE_TIMESTAMP),
    signer.signature,
  )
  // Arşiv damgasının girdisi imzanın tamamını kapsar ve bu paket onu
  // ÜRETMİYOR; okunduğunda kriptografik geçerliliği bildirilir ama neyi
  // damgaladığı bağlanmaz. Bunu sessizce "geçerli" saymak yanıltıcı
  // olurdu — seviye tespitinde de arşiv damgası seviye yükseltmiyor.
  check(
    'archive',
    [
      ...attributeValues(signer.unsignedAttributes, UnsignedAttribute.ARCHIVE_TIMESTAMP_V3),
      ...attributeValues(signer.unsignedAttributes, UnsignedAttribute.ARCHIVE_TIMESTAMP_V2),
    ],
    undefined,
  )
  return results
}

/** İmza seviyesini belirler. */
const detectCadesLevel = (
  signer: CmsSignerInfo,
  binding: Binding,
  timestamps: readonly CadesTimestampResult[],
): CadesLevel => {
  if (binding === 'missing') return 'CMS'
  const has = (oid: string): boolean => attributeValues(signer.unsignedAttributes, oid).length > 0
  const timestamped = timestamps.some(
    (timestamp) => timestamp.valid && timestamp.kind === 'signature',
  )

  if (
    timestamped &&
    (has(UnsignedAttribute.CERTIFICATE_VALUES) || has(UnsignedAttribute.REVOCATION_VALUES))
  ) {
    return 'LT'
  }
  if (timestamped) return 'T'
  if (signedAttribute(signer, SignedAttribute.SIGNATURE_POLICY_ID) !== undefined) return 'EPES'
  return 'BES'
}
