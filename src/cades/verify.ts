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

import {
  archiveTimestampInput,
  ATS_HASH_INDEX_OID,
  checkAtsHashIndex,
  digestFromOid,
  parseAtsHashIndex,
  readArchiveComponents,
} from './archive.js'
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
  /**
   * Yalnızca arşiv damgasında: `ATSHashIndex`, belgede o an bulunan
   * sertifika, iptal verisi ve imzalanmamış özniteliklerin **tamamını**
   * karşılıyor mu.
   *
   * `false` ise damga geçerli olabilir ama belgeye sonradan, damganın
   * korumadığı bir bileşen eklenmiştir.
   */
  readonly coversAllComponents?: boolean
  /** Kapsam eksikse nedeni. */
  readonly coverageReason?: string
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
    | 'archive-timestamp-partial-coverage'
    | 'archive-timestamp-v2-unverified'
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
  const timestamps = verifyCadesTimestamps(signer, cms, options.content)
  for (const timestamp of timestamps) {
    if (!timestamp.valid) {
      warnings.push({
        code: 'timestamp-invalid',
        message: `Zaman damgası doğrulanamadı: ${timestamp.reason ?? 'bilinmeyen sebep'}`,
      })
    } else if (timestamp.kind === 'archive' && timestamp.coversAllComponents === false) {
      warnings.push({
        code: 'archive-timestamp-partial-coverage',
        message:
          `Arşiv damgası belgedeki her bileşeni kapsamıyor: ${timestamp.coverageReason ?? ''} ` +
          'Damgadan sonra eklenen bileşenler onun korumasında değildir.',
      })
    }
  }
  if (
    attributeValues(signer.unsignedAttributes, UnsignedAttribute.ARCHIVE_TIMESTAMP_V2).length > 0
  ) {
    warnings.push({
      code: 'archive-timestamp-v2-unverified',
      message:
        'Belgede ATSv2 arşiv damgası var; girdi hesabı ATSv3ten farklı ve bu paket onu ' +
        'doğrulamıyor. Kriptografik geçerliliği bildiriliyor ama neyi damgaladığı bağlanmıyor.',
    })
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
const verifyCadesTimestamps = (
  signer: CmsSignerInfo,
  cms: Uint8Array,
  detachedContent: Uint8Array | undefined,
): readonly CadesTimestampResult[] => {
  const results: CadesTimestampResult[] = []

  for (const token of attributeValues(
    signer.unsignedAttributes,
    UnsignedAttribute.SIGNATURE_TIMESTAMP,
  )) {
    results.push(describe('signature', token.raw, { data: signer.signature }))
  }

  const archiveTokens = attributeValues(
    signer.unsignedAttributes,
    UnsignedAttribute.ARCHIVE_TIMESTAMP_V3,
  )
  for (const token of archiveTokens) {
    results.push(verifyArchiveTimestamp(token, archiveTokens, cms, detachedContent))
  }

  // ATSv2'nin girdi hesabı ATSv3ten farklıdır (TS 101 733 v1.8.3 §6.4.1) ve
  // bu paket onu ÜRETMİYOR. Bağımsız olarak doğrulanamadığı için neyi
  // damgaladığı bağlanmıyor; sessizce "geçerli" saymak yanıltıcı olurdu.
  for (const token of attributeValues(
    signer.unsignedAttributes,
    UnsignedAttribute.ARCHIVE_TIMESTAMP_V2,
  )) {
    results.push(describe('archive', token.raw, {}))
  }

  return results
}

/** Jetonu doğrulayıp sonucu biçimlendirir. */
const describe = (
  kind: 'signature' | 'archive',
  token: Uint8Array,
  options: { readonly data?: Uint8Array },
): CadesTimestampResult => {
  const outcome = verifyTimestampToken(token, options)
  return outcome.valid
    ? {
        kind,
        valid: true,
        genTime: outcome.info.genTime,
        policyOid: outcome.info.policyOid,
      }
    : { kind, valid: false, reason: outcome.reason }
}

/**
 * `archive-time-stamp-v3` doğrular — TS 101 733 §6.4.3.
 *
 * Girdi, jetonun kendi `unsignedAttrs`ındaki `ats-hash-index` **olduğu
 * gibi** kullanılarak yeniden kuruluyor. İndeksin belgeyi karşılayıp
 * karşılamadığı AYRICA denetleniyor: indeksi girdiye koyup sonra ona
 * bakmamak, damganın neyi kapsadığını söylememek olurdu.
 */
const verifyArchiveTimestamp = (
  token: DerNode,
  allArchiveTokens: readonly DerNode[],
  cms: Uint8Array,
  detachedContent: Uint8Array | undefined,
): CadesTimestampResult => {
  let indexDer: Uint8Array
  try {
    indexDer = atsHashIndexOf(token.raw)
  } catch (error) {
    return {
      kind: 'archive',
      valid: false,
      reason: `ats-hash-index okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  let hash: CmsDigest
  let index: ReturnType<typeof parseAtsHashIndex>
  try {
    index = parseAtsHashIndex(indexDer)
    const resolved = digestFromOid(index.hashAlgorithmOid)
    if (resolved === undefined) {
      return {
        kind: 'archive',
        valid: false,
        reason: `ATSHashIndex özet algoritması desteklenmiyor: ${index.hashAlgorithmOid}`,
      }
    }
    hash = resolved
  } catch (error) {
    return {
      kind: 'archive',
      valid: false,
      reason: `ATSHashIndex çözümlenemedi: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  let input: Uint8Array
  let components: ReturnType<typeof readArchiveComponents>
  try {
    components = readArchiveComponents(cms)
    input = archiveTimestampInput(components, indexDer, hash, detachedContent)
  } catch (error) {
    return {
      kind: 'archive',
      valid: false,
      reason: `Arşiv girdisi kurulamadı: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  const outcome = verifyTimestampToken(token.raw, { data: input })
  if (!outcome.valid) return { kind: 'archive', valid: false, reason: outcome.reason }

  // §6.4.2, ikinci denetim: indeks belgedeki bileşenleri karşılıyor mu.
  //
  // Bu damganın KENDİ özniteliği indekste bulunmaz — indeks o damga
  // istenirken hesaplandı, öznitelik henüz yoktu. Aynısı bu damgadan SONRA
  // eklenmiş arşiv damgaları için de geçerli; onlar da indekste yok
  // oldukları için hariç tutuluyor. Arşiv damgası OLMAYAN bileşenler hariç
  // tutulmuyor: sonradan eklenen bir sertifika ya da öznitelik tam olarak
  // burada yakalanmalı.
  const indexed = new Set(index.unsignedAttrsHashIndex.map((value) => hexOf(value)))
  const exclude = allArchiveTokens
    .map((other) => archiveAttributeOf(components, other.raw))
    .filter((raw): raw is Uint8Array => raw !== undefined)
    .filter((raw) => !indexed.has(hexOf(digestOf(hash, raw))))

  const coverage = checkAtsHashIndex(index, components, hash, exclude)
  return {
    kind: 'archive',
    valid: true,
    genTime: outcome.info.genTime,
    policyOid: outcome.info.policyOid,
    coversAllComponents: coverage.complete,
    ...(coverage.complete ? {} : { coverageReason: coverage.reason }),
  }
}

/** Jetonun `unsignedAttrs`ındaki `ats-hash-index` değerini verir. */
const atsHashIndexOf = (token: Uint8Array): Uint8Array => {
  const signer = parseCmsSignedData(token).signerInfos[0]
  if (signer === undefined) throw new VerificationError('Jetonda imzacı yok.')
  const values = attributeValues(signer.unsignedAttributes, ATS_HASH_INDEX_OID)
  const first = values[0]
  if (first === undefined) {
    throw new VerificationError(
      'archive-time-stamp-v3 jetonunda ats-hash-index yok; TS 101 733 §6.4.3 zorunlu kılıyor.',
    )
  }
  if (values.length > 1) {
    throw new VerificationError('ats-hash-index tek değerli olmalı; birden çok bulundu.')
  }
  return first.raw
}

/**
 * Bir arşiv jetonunu SARAN `Attribute`ın ham baytlarını bulur.
 *
 * İndeks öznitelikleri bütün hâlinde özetliyor; jetonun kendisi değil,
 * onu içeren `Attribute` aranmalı.
 */
const archiveAttributeOf = (
  components: ReturnType<typeof readArchiveComponents>,
  token: Uint8Array,
): Uint8Array | undefined =>
  components.unsignedAttributeInstances.find((attribute) => contains(attribute, token))

/** `haystack` içinde `needle` bayt dizisi geçiyor mu. */
const contains = (haystack: Uint8Array, needle: Uint8Array): boolean => {
  if (needle.length === 0 || needle.length > haystack.length) return false
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

/** Özet — indeks karşılaştırmaları için. */
const digestOf = (hash: CmsDigest, bytes: Uint8Array): Uint8Array => cmsDigest(hash, bytes)

/** Baytları onaltılığa çevirir. */
const hexOf = (bytes: Uint8Array): string => {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
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

  const longTerm =
    timestamped &&
    (has(UnsignedAttribute.CERTIFICATE_VALUES) || has(UnsignedAttribute.REVOCATION_VALUES))
  if (longTerm) {
    // LTA, LT'nin ÜZERİNE kurulur. Doğrulanmış bir arşiv damgası
    // gerekiyor: gömülü ama tutmayan bir damga seviyeyi yükseltmez.
    const archived = timestamps.some((timestamp) => timestamp.valid && timestamp.kind === 'archive')
    return archived ? 'LTA' : 'LT'
  }
  if (timestamped) return 'T'
  if (signedAttribute(signer, SignedAttribute.SIGNATURE_POLICY_ID) !== undefined) return 'EPES'
  return 'BES'
}
