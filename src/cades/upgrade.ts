import { SigningError } from '../core/errors.js'
import { cmsAttribute, cmsDigest, type CmsDigest } from '../pki/cms-build.js'
import { parseCmsSignedData } from '../pki/cms.js'
import { buildTimestampRequest, verifyTimestampToken } from '../pki/tsp.js'

import {
  archiveTimestampInput,
  ATS_HASH_INDEX_OID,
  buildAtsHashIndex,
  readArchiveComponents,
} from './archive.js'
import {
  certificateValuesAttribute,
  revocationValuesAttribute,
  timestampAttribute,
} from './attributes.js'
import { UnsignedAttribute } from './constants.js'
import { addUnsignedAttributes } from './edit.js'

/**
 * CAdES seviye yükseltme — **T** ve **LT**.
 *
 * XAdES tarafındaki desenin aynısı: ağ isteği burada yok.
 * {@link cadesTimestampRequest} istek baytlarını üretir, aradaki HTTP
 * çağrısını çağıran yapar, {@link cadesUpgrade} jetonu yerleştirir.
 *
 * ## Neden imzayı bozmuyor
 *
 * Eklenen her şey `unsignedAttrs` altına gider ve o alan imzaya **dâhil
 * değildir** — imza yalnızca `signedAttrs` üzerinde hesaplanır. Adı da
 * bunu söylüyor.
 */

/** {@link cadesTimestampRequest} seçenekleri. */
export interface CadesTimestampRequestInput {
  /** İmzalı CMS yapısı (DER). */
  readonly cms: Uint8Array
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digest?: CmsDigest
  readonly policyOid?: string
  readonly nonce?: bigint
  readonly requestCertificate?: boolean
}

/**
 * CAdES imzası için RFC 3161 zaman damgası isteği üretir.
 *
 * ETSI TS 101 733 §6.1.1: damgalanan şey, `SignerInfo` imza alanındaki
 * **OCTET STRING'in DEĞERİDİR** — sarmalayıcı değil. Sarmalayıcıyı
 * damgalamak, kendi doğrulayıcınız dışında kabul edilmeyen bir jeton
 * üretir.
 *
 * @param options - {@link CadesTimestampRequestInput}
 * @returns `TimeStampReq` DER kodlaması
 */
export const cadesTimestampRequest = (options: CadesTimestampRequestInput): Uint8Array => {
  const digest = options.digest ?? 'sha256'
  const signature = signerSignature(options.cms)
  return buildTimestampRequest({
    messageImprint: cmsDigest(digest, signature),
    hashAlgorithm: digest,
    ...(options.policyOid === undefined ? {} : { policyOid: options.policyOid }),
    ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    ...(options.requestCertificate === undefined
      ? {}
      : { requestCertificate: options.requestCertificate }),
  })
}

/** T seviyesine yükseltme. */
export interface CadesUpgradeToTimestamp {
  readonly cms: Uint8Array
  readonly to: 'T'
  /** TSA'dan alınan jeton. */
  readonly token: Uint8Array
  /** Jetonun bu imzayı damgaladığı doğrulansın mı. Varsayılan `true`. */
  readonly verifyToken?: boolean
  readonly digest?: CmsDigest
}

/** LT seviyesine yükseltme. */
export interface CadesUpgradeToLongTerm {
  readonly cms: Uint8Array
  readonly to: 'LT'
  /** Gömülecek sertifikalar (DER). */
  readonly certificates: readonly Uint8Array[]
  /** Gömülecek OCSP yanıtları — **`BasicOCSPResponse`** DER'i. */
  readonly ocspResponses?: readonly Uint8Array[]
  /** Gömülecek CRL'ler (`CertificateList` DER'i). */
  readonly crls?: readonly Uint8Array[]
}

/** {@link cadesUpgrade} seçenekleri. */
export type CadesUpgradeOptions = CadesUpgradeToTimestamp | CadesUpgradeToLongTerm

/**
 * CAdES imzasını bir üst seviyeye yükseltir.
 *
 * @param options - {@link CadesUpgradeOptions}
 * @returns Yükseltilmiş CMS yapısı (DER)
 * @throws {SigningError} Yapı okunamazsa ya da veri bu imzayla bağdaşmazsa
 */
export const cadesUpgrade = (options: CadesUpgradeOptions): Uint8Array => {
  if (options.to === 'T') {
    if (options.verifyToken ?? true) {
      const outcome = verifyTimestampToken(options.token)
      if (!outcome.valid) {
        throw new SigningError(`Zaman damgası jetonu doğrulanamadı: ${outcome.reason}`)
      }
      const expected = cmsDigest(options.digest ?? 'sha256', signerSignature(options.cms))
      if (Buffer.from(outcome.info.messageImprint).compare(Buffer.from(expected)) !== 0) {
        throw new SigningError(
          'Jeton bu imzayı damgalamamış — messageImprint eşleşmiyor. ' +
            'İsteği üreten CMS ile yükseltilen CMS aynı olmalı.',
        )
      }
    }
    return addUnsignedAttributes(options.cms, [
      timestampAttribute(UnsignedAttribute.SIGNATURE_TIMESTAMP, options.token),
    ])
  }

  const ocspResponses = options.ocspResponses ?? []
  const crls = options.crls ?? []
  if (ocspResponses.length === 0 && crls.length === 0) {
    throw new SigningError(
      'LT seviyesi iptal kanıtı olmadan anlamsız: en az bir OCSP yanıtı ya da CRL verilmeli.',
    )
  }
  if (options.certificates.length === 0) {
    throw new SigningError('LT seviyesi için en az bir sertifika verilmeli.')
  }
  return addUnsignedAttributes(options.cms, [
    certificateValuesAttribute(UnsignedAttribute.CERTIFICATE_VALUES, options.certificates),
    revocationValuesAttribute(UnsignedAttribute.REVOCATION_VALUES, crls, ocspResponses),
  ])
}

/** İmzacının ham imza baytlarını verir. */
const signerSignature = (cms: Uint8Array): Uint8Array => {
  const signer = parseCmsSignedData(cms).signerInfos[0]
  if (signer === undefined) throw new SigningError('CMS yapısında imzacı yok.')
  return signer.signature
}

/** {@link cadesArchiveTimestamp} seçenekleri. */
export interface CadesArchiveTimestampOptions {
  /** Yükseltilecek CMS yapısı (DER). */
  readonly cms: Uint8Array
  /**
   * Ayrık imzada dışarıda tutulan veri.
   *
   * Zorunlu: girdinin ikinci bileşeni imzalanan verinin özetidir ve ayrık
   * imzada veri yapının içinde yoktur.
   */
  readonly content?: Uint8Array
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digest?: CmsDigest
  readonly policyOid?: string
  readonly nonce?: bigint
  readonly requestCertificate?: boolean
}

/** Jetonu beklenen arşiv zaman damgası. */
export interface PendingCadesArchiveTimestamp {
  /** TSA'ya `application/timestamp-query` olarak gönderilecek istek. */
  readonly request: Uint8Array
  /** Damgalanan girdinin özeti. */
  readonly messageImprint: Uint8Array
  /** Damgalanan baytlar; girdiyi kendiniz incelemek isterseniz. */
  readonly stampedBytes: Uint8Array
  /** Girdiye giren `ATSHashIndex` (DER). */
  readonly atsHashIndex: Uint8Array
  /**
   * Jetonu yerleştirir ve LTA seviyesindeki CMS'i döndürür.
   *
   * İki iş yapılıyor: `ats-hash-index` jetonun KENDİ `unsignedAttrs`ına
   * ekleniyor (§6.4.3 bunu şart koşuyor; imzalanmamış alan olduğu için
   * jetonun imzası bozulmuyor), sonra jeton `archive-time-stamp-v3`
   * özniteliği olarak imzaya ekleniyor.
   *
   * @throws {SigningError} Jeton bu girdiyi damgalamıyorsa
   */
  readonly finish: (token: Uint8Array, options?: { readonly verifyToken?: boolean }) => Uint8Array
}

/**
 * Arşiv zaman damgası (LTA) hazırlar — ETSI TS 101 733 §6.4.3.
 *
 * İstek ile yerleştirme **tek bir kapanışta** tutuluyor: girdinin dördüncü
 * bileşeni `ATSHashIndex` ve o indeks iki yerde ayrı ayrı hesaplanırsa
 * baytları ayrışabilir; ayrıştığı an damga hiçbir doğrulayıcıda tutmaz.
 *
 * @param options - {@link CadesArchiveTimestampOptions}
 * @returns Jetonu bekleyen damga
 *
 * @example
 * ```ts
 * const bekleyen = cadesArchiveTimestamp({ cms: ltImza })
 * const yanit = await fetch(tsaUrl, {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/timestamp-query' },
 *   body: bekleyen.request,
 * })
 * const lta = bekleyen.finish(
 *   parseTimestampResponse(new Uint8Array(await yanit.arrayBuffer())),
 * )
 * ```
 */
export const cadesArchiveTimestamp = (
  options: CadesArchiveTimestampOptions,
): PendingCadesArchiveTimestamp => {
  const digest = options.digest ?? 'sha256'
  const components = readArchiveComponents(options.cms)
  const atsHashIndex = buildAtsHashIndex(components, digest)
  const stampedBytes = archiveTimestampInput(components, atsHashIndex, digest, options.content)
  const messageImprint = cmsDigest(digest, stampedBytes)

  return {
    request: buildTimestampRequest({
      messageImprint,
      hashAlgorithm: digest,
      ...(options.policyOid === undefined ? {} : { policyOid: options.policyOid }),
      ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
      ...(options.requestCertificate === undefined
        ? {}
        : { requestCertificate: options.requestCertificate }),
    }),
    messageImprint,
    stampedBytes,
    atsHashIndex,
    finish: (token, finishOptions = {}): Uint8Array => {
      if (finishOptions.verifyToken !== false) {
        const outcome = verifyTimestampToken(token, {
          data: stampedBytes,
          ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
        })
        if (!outcome.valid) {
          throw new SigningError(`Arşiv damgası bu imzayı damgalamıyor: ${outcome.reason}`)
        }
      }
      // `ats-hash-index` jetonun kendi imzacısına ekleniyor. Jetonun imzası
      // `signedAttrs` üzerinde; `unsignedAttrs` ona dâhil değil.
      const withIndex = addUnsignedAttributes(token, [
        cmsAttribute(ATS_HASH_INDEX_OID, atsHashIndex),
      ])
      return addUnsignedAttributes(options.cms, [
        timestampAttribute(UnsignedAttribute.ARCHIVE_TIMESTAMP_V3, withIndex),
      ])
    },
  }
}
