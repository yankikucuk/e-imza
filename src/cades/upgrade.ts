import { asSequence, decodeDer, derSetOf, type DerNode } from '../asn1/der.js'
import { SigningError } from '../core/errors.js'
import { cmsDigest, type CmsDigest } from '../pki/cms-build.js'
import { parseCmsSignedData } from '../pki/cms.js'
import { buildTimestampRequest, verifyTimestampToken } from '../pki/tsp.js'

import {
  certificateValuesAttribute,
  revocationValuesAttribute,
  timestampAttribute,
} from './attributes.js'
import { UnsignedAttribute } from './constants.js'

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

/**
 * `SignerInfo`ya imzalanmamış öznitelik ekler.
 *
 * Yapı **yeniden kodlanmaz**: `SignerInfo`nun kaynaktaki baytları alınır,
 * yalnızca `unsignedAttrs` alanı değiştirilir ve dış kaplar yeniden
 * kurulur. Yeniden kodlamak, kaynağın DER'e tam uymadığı durumlarda
 * `signedAttrs` baytlarını değiştirir ve imza tutmaz.
 */
const addUnsignedAttributes = (cms: Uint8Array, attributes: readonly Uint8Array[]): Uint8Array => {
  const contentInfo = asSequence(decodeDer(cms))
  const contentNode = contentInfo[1]
  if (contentNode === undefined) throw new SigningError('ContentInfo içeriği yok.')
  const signedDataNode = contentNode.children[0]
  if (signedDataNode === undefined) throw new SigningError('SignedData yok.')
  const fields = asSequence(signedDataNode)

  const signerInfosIndex = findLastSetIndex(fields)
  const signerInfosNode = fields[signerInfosIndex]
  if (signerInfosNode === undefined) throw new SigningError('signerInfos yok.')
  const signers = signerInfosNode.children
  const signer = signers[0]
  if (signer === undefined) throw new SigningError('CMS yapısında imzacı yok.')

  const signerFields = asSequence(signer)
  const unsignedIndex = signerFields.findIndex(
    (field) => field.tagClass === 'context' && field.tagNumber === 1,
  )
  // Var olan öznitelikler korunur; yenileri eklenir. Zaman damgası üstüne
  // zaman damgası eklenebilmesi bunu gerektiriyor.
  const existing =
    unsignedIndex === -1
      ? []
      : (signerFields[unsignedIndex]?.children ?? []).map((node) => node.raw)
  const kept =
    unsignedIndex === -1
      ? signerFields.map((field) => field.raw)
      : signerFields.filter((_, index) => index !== unsignedIndex).map((field) => field.raw)

  const merged = derSetOf(...existing, ...attributes)
  const tagged = new Uint8Array(merged)
  tagged[0] = 0xa1

  const newSigner = wrapSequence([...kept, tagged])
  const newSignerInfos = wrapSet(signers.map((node, index) => (index === 0 ? newSigner : node.raw)))
  const newSignedData = wrapSequence(
    fields.map((field, index) => (index === signerInfosIndex ? newSignerInfos : field.raw)),
  )
  const newContent = wrapExplicit(0, newSignedData)
  return wrapSequence([contentInfo[0]?.raw ?? new Uint8Array(0), newContent])
}

/** `signerInfos` alanının konumu — yapının SON `SET`i. */
const findLastSetIndex = (fields: readonly DerNode[]): number => {
  for (let index = fields.length - 1; index >= 0; index -= 1) {
    const field = fields[index]
    if (field?.tagClass === 'universal' && field.tagNumber === 17) return index
  }
  return -1
}

/* Kodlanmış parçaları yeniden sarmak için küçük yardımcılar. Uzunluk
   yeniden hesaplandığı için `der.ts` yazıcıları kullanılıyor. */
const wrapSequence = (items: readonly Uint8Array[]): Uint8Array => encode(0x30, items)
const wrapSet = (items: readonly Uint8Array[]): Uint8Array => encode(0x31, items)
const wrapExplicit = (tagNumber: number, item: Uint8Array): Uint8Array =>
  encode(0xa0 | tagNumber, [item])

/** Verilen etiketle bir kurgusal değer kodlar. */
const encode = (tag: number, items: readonly Uint8Array[]): Uint8Array => {
  let length = 0
  for (const item of items) length += item.length
  const header: number[] = [tag]
  if (length < 0x80) {
    header.push(length)
  } else {
    const bytes: number[] = []
    let remaining = length
    while (remaining > 0) {
      bytes.unshift(remaining & 0xff)
      remaining = Math.floor(remaining / 256)
    }
    header.push(0x80 | bytes.length, ...bytes)
  }
  const out = new Uint8Array(header.length + length)
  out.set(header)
  let offset = header.length
  for (const item of items) {
    out.set(item, offset)
    offset += item.length
  }
  return out
}
