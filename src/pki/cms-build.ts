import { createHash } from 'node:crypto'

import {
  derExplicit,
  derImplicitSet,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  derSetOf,
} from '../asn1/der.js'
import { SigningError } from '../core/errors.js'

import { CmsOid } from './cms.js'
import { certificateNames, serialNumberNode } from './extensions.js'

/**
 * CMS `SignedData` üretimi — RFC 5652.
 *
 * Okuma tarafı {@link ./cms.js} içinde; ikisi ayrı dosyada çünkü okuma
 * zaman damgası için tek başına gerekiyordu ve üretim yalnızca CAdES ile
 * geldi.
 *
 * ## İmzalanan baytlar
 *
 * `signedAttrs` varsa imza **onların DER kodlaması** üzerinde hesaplanır ve
 * o kodlamada dış etiket `[0] IMPLICIT` değil `SET`tir (RFC 5652 §5.4).
 * Yapı iki kez kodlanmaz: `SET` biçimi bir kez üretilir, imza onun
 * üzerinde alınır, gömülürken yalnızca ilk BAYT `[0]`a çevrilir. Uzunluk
 * alanı değişmediği için bu güvenli — ve yeniden kodlamanın kaynağı
 * değiştirme riski ortadan kalkıyor.
 */

/** Desteklenen özet algoritmaları. */
export type CmsDigest = 'sha256' | 'sha384' | 'sha512'

/** Özet algoritması → OID. */
export const CMS_DIGEST_OID: Readonly<Record<CmsDigest, string>> = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

/** RSA PKCS#1 v1.5 imza algoritması OID'leri. */
const RSA_SIGNATURE_OID: Readonly<Record<CmsDigest, string>> = {
  sha256: '1.2.840.113549.1.1.11',
  sha384: '1.2.840.113549.1.1.12',
  sha512: '1.2.840.113549.1.1.13',
}

/** ECDSA imza algoritması OID'leri. */
const ECDSA_SIGNATURE_OID: Readonly<Record<CmsDigest, string>> = {
  sha256: '1.2.840.10045.4.3.2',
  sha384: '1.2.840.10045.4.3.3',
  sha512: '1.2.840.10045.4.3.4',
}

/**
 * İmza algoritması tanımlayıcısını kodlar.
 *
 * ECDSA'da `parameters` alanı **yazılmaz**. RFC 5758 §3.2 bunu şart koşar
 * ve `PKI.js#464` tam olarak fazladan parametre kabul edilmesinden
 * açılmıştı. RSA'da ise `NULL` yazılır — orada atlamak eski
 * doğrulayıcıları şaşırtır.
 */
export const signatureAlgorithmIdentifier = (kind: 'rsa' | 'ec', digest: CmsDigest): Uint8Array =>
  kind === 'ec'
    ? derSequence(derOid(ECDSA_SIGNATURE_OID[digest]))
    : derSequence(derOid(RSA_SIGNATURE_OID[digest]), derNull())

/** Özet algoritması tanımlayıcısını kodlar. */
export const digestAlgorithmIdentifier = (digest: CmsDigest): Uint8Array =>
  derSequence(derOid(CMS_DIGEST_OID[digest]), derNull())

/** Bir CMS özniteliğini kodlar. */
export const cmsAttribute = (oid: string, ...values: readonly Uint8Array[]): Uint8Array =>
  derSequence(derOid(oid), derSetOf(...values))

/**
 * İmzalanacak `signedAttrs` baytlarını üretir.
 *
 * Dönen değer `SET` etiketiyle başlar — imza tam olarak bunun üzerinde
 * hesaplanır.
 *
 * @param attributes - Kodlanmış öznitelikler
 * @returns `SET OF Attribute` kodlaması
 */
export const encodeSignedAttributes = (attributes: readonly Uint8Array[]): Uint8Array => {
  if (attributes.length === 0) {
    throw new SigningError('İmzalanmış öznitelik listesi boş olamaz.')
  }
  return derSetOf(...attributes)
}

/** {@link buildSignedData} girdisi. */
export interface SignedDataInput {
  /** Sarmalanan içeriğin türü; varsayılan `id-data`. */
  readonly contentType?: string
  /**
   * Sarmalanan içerik.
   *
   * `attached` `false` ise içerik yapıya gömülmez (ayrık imza) ama özet
   * yine onun üzerinden alınır.
   */
  readonly content: Uint8Array
  /** İçerik gömülsün mü; varsayılan `true`. */
  readonly attached?: boolean
  /** İmzalayan sertifika (DER). */
  readonly certificate: Uint8Array
  /** Yapıya gömülecek diğer sertifikalar (DER). */
  readonly chain?: readonly Uint8Array[]
  readonly digest: CmsDigest
  readonly keyKind: 'rsa' | 'ec'
  /** `SET` etiketiyle başlayan imzalanmış öznitelik baytları. */
  readonly signedAttributes: Uint8Array
  /** Ham imza değeri. */
  readonly signature: Uint8Array
  /** Kodlanmış imzalanmamış öznitelikler. */
  readonly unsignedAttributes?: readonly Uint8Array[]
}

/**
 * CMS `ContentInfo` / `SignedData` yapısını kurar.
 *
 * @param input - {@link SignedDataInput}
 * @returns `ContentInfo` DER kodlaması
 */
export const buildSignedData = (input: SignedDataInput): Uint8Array => {
  const contentType = input.contentType ?? CmsOid.DATA
  const attached = input.attached ?? true

  // `signedAttrs` iletimde `[0] IMPLICIT` etiketiyle yazılır; imza ise
  // `SET` biçiminin üzerinde alınmıştır. Yalnızca ilk bayt değişir.
  const embeddedAttributes = derImplicitSet(0, input.signedAttributes)

  const names = certificateNames(input.certificate)
  const signerInfo = derSequence(
    derInteger(1n),
    derSequence(names.issuer, serialNumberNode(input.certificate).raw),
    digestAlgorithmIdentifier(input.digest),
    embeddedAttributes,
    signatureAlgorithmIdentifier(input.keyKind, input.digest),
    derOctetString(input.signature),
    ...(input.unsignedAttributes === undefined || input.unsignedAttributes.length === 0
      ? []
      : [derImplicitSet(1, derSetOf(...input.unsignedAttributes))]),
  )

  const certificates = [input.certificate, ...(input.chain ?? [])]
  const encapsulated = derSequence(
    derOid(contentType),
    ...(attached ? [derExplicit(0, derOctetString(input.content))] : []),
  )

  // RFC 5652 §5.1: `eContentType` `id-data` değilse sürüm 3.
  const version = contentType === CmsOid.DATA ? 1n : 3n

  return derSequence(
    derOid(CmsOid.SIGNED_DATA),
    derExplicit(
      0,
      derSequence(
        derInteger(version),
        derSetOf(digestAlgorithmIdentifier(input.digest)),
        encapsulated,
        derImplicitSet(0, derSetOf(...certificates)),
        derSetOf(signerInfo),
      ),
    ),
  )
}

/** İçeriğin özetini alır. */
export const cmsDigest = (algorithm: CmsDigest, data: Uint8Array): Uint8Array =>
  new Uint8Array(createHash(algorithm).update(Buffer.from(data)).digest())
