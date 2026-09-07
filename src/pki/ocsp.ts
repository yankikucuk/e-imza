import { createHash, createVerify, X509Certificate } from 'node:crypto'

import {
  asBitString,
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asTime,
  decodeDer,
  derExplicit,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  DerTag,
  findContext,
  type DerNode,
} from '../asn1/der.js'
import { timingSafeEqual } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

import { certificateNames, publicKeyBits, serialNumberNode } from './extensions.js'

/**
 * OCSP — çevrimiçi sertifika durum protokolü (RFC 6960).
 *
 * LT seviyesine yükseltmek için gereken iptal kanıtını üretir. Ağ isteği
 * bu modülde **yoktur**: {@link buildOcspRequest} baytları üretir,
 * {@link parseOcspResponse} baytları okur, aradaki HTTP çağrısını çağıran
 * yapar.
 */

const OID = {
  BASIC_RESPONSE: '1.3.6.1.5.5.7.48.1.1',
  NONCE: '1.3.6.1.5.5.7.48.1.2',
} as const

/** Özet algoritması OID'leri. */
const DIGEST_OID: Readonly<Record<string, string>> = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

const DIGEST_NAME: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(DIGEST_OID).map(([name, oid]) => [oid, name]),
)

/** İmza algoritması OID'leri → özet adı. */
const SIGNATURE_HASH: Readonly<Record<string, string>> = {
  '1.2.840.113549.1.1.5': 'sha1',
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
}

/** {@link buildOcspRequest} seçenekleri. */
export interface OcspRequestOptions {
  /** Durumu sorulan sertifika (DER). */
  readonly certificate: Uint8Array
  /** Onu düzenleyen sertifika (DER). */
  readonly issuer: Uint8Array
  /**
   * `CertID` özet algoritması; varsayılan `sha1`.
   *
   * **Bu, paketin "SHA-1 yok" ilkesinin bilinçli istisnası.** Buradaki
   * özet bir GÜVENLİK özeti değil, bir ADLANDIRMA özeti: yanıtlayıcının
   * hangi sertifikanın sorulduğunu bulmasına yarıyor ve çakışma bulmak
   * saldırgana bir şey kazandırmıyor. RFC 6960 SHA-1 desteğini şart
   * koşuyor ve sahadaki yanıtlayıcıların ezici çoğunluğu başka bir şey
   * kabul etmiyor; `sha256` verildiğinde pek çok yanıtlayıcı "unknown"
   * dönüyor.
   */
  readonly hashAlgorithm?: 'sha1' | 'sha256' | 'sha384' | 'sha512'
  /** Tekrar saldırısına karşı tek kullanımlık değer. */
  readonly nonce?: Uint8Array
}

/** İç kullanım: `CertID` yapısı ve onu kuran parçalar. */
interface CertId {
  readonly hashAlgorithm: string
  readonly issuerNameHash: Uint8Array
  readonly issuerKeyHash: Uint8Array
  readonly serialNumber: bigint
}

/**
 * Sorulan sertifika için `CertID` değerlerini hesaplar.
 *
 * İki özetin kaynağı sıkça karıştırılır ve karıştırıldığında yanıtlayıcı
 * sessizce "unknown" döner:
 * - `issuerNameHash`, **sorulan sertifikanın `issuer` alanının** DER
 *   kodlaması üzerinden alınır (RFC 6960 §4.1.1),
 * - `issuerKeyHash`, **düzenleyen sertifikanın açık anahtar BIT STRING
 *   İÇERİĞİ** üzerinden — `SubjectPublicKeyInfo`nun tamamı üzerinden değil.
 */
const computeCertId = (
  certificate: Uint8Array,
  issuer: Uint8Array,
  hashAlgorithm: string,
): CertId => {
  const hash = (data: Uint8Array): Uint8Array =>
    new Uint8Array(createHash(hashAlgorithm).update(Buffer.from(data)).digest())
  return {
    hashAlgorithm,
    issuerNameHash: hash(certificateNames(certificate).issuer),
    issuerKeyHash: hash(publicKeyBits(issuer)),
    serialNumber: asInteger(serialNumberNode(certificate)),
  }
}

/** `CertID` yapısını kodlar. */
const encodeCertId = (id: CertId): Uint8Array => {
  const oid = DIGEST_OID[id.hashAlgorithm]
  if (oid === undefined) throw new RangeError(`Desteklenmeyen özet: ${id.hashAlgorithm}`)
  return derSequence(
    derSequence(derOid(oid), derNull()),
    derOctetString(id.issuerNameHash),
    derOctetString(id.issuerKeyHash),
    derInteger(id.serialNumber),
  )
}

/**
 * RFC 6960 `OCSPRequest` üretir.
 *
 * @param options - {@link OcspRequestOptions}
 * @returns İstek DER kodlaması — yanıtlayıcıya `application/ocsp-request` olarak gönderilir
 *
 * @example
 * ```ts
 * const [adres] = ocspResponderUrls(sertifika)
 * const istek = buildOcspRequest({ certificate: sertifika, issuer: kok })
 * const yanit = await fetch(adres!, {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/ocsp-request' },
 *   body: istek,
 * })
 * ```
 */
export const buildOcspRequest = (options: OcspRequestOptions): Uint8Array => {
  const id = computeCertId(options.certificate, options.issuer, options.hashAlgorithm ?? 'sha1')
  const request = derSequence(encodeCertId(id))

  // requestExtensions [2] EXPLICIT — yalnızca nonce verilmişse. Nonce
  // değeri, uzantı kabuğunun OCTET STRING'i İÇİNDE ayrıca bir OCTET STRING
  // olarak sarılır; tek katman yazmak yanıtlayıcıların çoğunu şaşırtır.
  const extensions =
    options.nonce === undefined
      ? []
      : [
          derExplicit(
            2,
            derSequence(
              derSequence(derOid(OID.NONCE), derOctetString(derOctetString(options.nonce))),
            ),
          ),
        ]

  return derSequence(derSequence(derSequence(request), ...extensions))
}

/** Sertifikanın iptal durumu. */
export type CertificateStatus =
  | { readonly status: 'good' }
  | { readonly status: 'revoked'; readonly revokedAt: Date; readonly reason?: number }
  | { readonly status: 'unknown' }

/** Çözümlenmiş `BasicOCSPResponse`. */
export interface OcspResponse {
  /** Yanıtın imzalandığı `tbsResponseData` baytları — imza bunun üzerindedir. */
  readonly tbsBytes: Uint8Array
  /** Yanıtlayıcının ürettiği zaman. */
  readonly producedAt: Date
  /** Yanıtlayıcının gömdüğü sertifikalar (DER). */
  readonly certificates: readonly Uint8Array[]
  readonly signatureAlgorithmOid: string
  readonly signature: Uint8Array
  /** Her sorulan sertifika için bir yanıt. */
  readonly responses: readonly SingleOcspResponse[]
  /** Yanıttaki tek kullanımlık değer, varsa. */
  readonly nonce?: Uint8Array
  /** Yanıtın tamamı (DER) — LT seviyesine gömülecek olan budur. */
  readonly der: Uint8Array
}

/** Tek bir sertifikaya ait yanıt. */
export interface SingleOcspResponse {
  readonly certId: CertId
  readonly status: CertificateStatus
  readonly thisUpdate: Date
  readonly nextUpdate?: Date
}

/** OCSP yanıt durumları (RFC 6960 §4.2.1). */
const RESPONSE_STATUS: Readonly<Record<number, string>> = {
  0: 'başarılı',
  1: 'hatalı istek',
  2: 'iç hata',
  3: 'daha sonra deneyin',
  5: 'imza gerekli',
  6: 'yetkisiz',
}

/**
 * `OCSPResponse` çözümler.
 *
 * @param bytes - Yanıtın DER kodlaması
 * @returns Çözümlenmiş temel yanıt
 * @throws {DerParseError} Yanıtlayıcı isteği reddettiyse ya da yapı bozuksa
 */
export const parseOcspResponse = (bytes: Uint8Array): OcspResponse => {
  const fields = asSequence(decodeDer(bytes))
  const statusNode = fields[0]
  if (statusNode === undefined) throw new DerParseError(0, 'responseStatus yok.')
  // ENUMERATED, INTEGER ile aynı içerik kodlamasını kullanır.
  const status = statusNode.content[0] ?? 255
  if (status !== 0) {
    throw new DerParseError(
      0,
      `OCSP yanıtlayıcı isteği reddetti (${String(status)}: ${RESPONSE_STATUS[status] ?? 'bilinmiyor'}).`,
    )
  }

  const responseBytes = findContext(fields, 0)?.children[0]
  if (responseBytes === undefined) throw new DerParseError(0, 'responseBytes yok.')
  const responseFields = asSequence(responseBytes)
  const typeNode = responseFields[0]
  const payloadNode = responseFields[1]
  if (typeNode === undefined || payloadNode === undefined) {
    throw new DerParseError(0, 'ResponseBytes yapısı eksik.')
  }
  if (asOid(typeNode) !== OID.BASIC_RESPONSE) {
    throw new DerParseError(0, `Desteklenmeyen yanıt türü: ${asOid(typeNode)}`)
  }

  const basic = asSequence(decodeDer(asOctetString(payloadNode)))
  const tbs = basic[0]
  const algorithmNode = basic[1]
  const signatureNode = basic[2]
  if (tbs === undefined || algorithmNode === undefined || signatureNode === undefined) {
    throw new DerParseError(0, 'BasicOCSPResponse yapısı eksik.')
  }

  const certificates = (findContext(basic, 0)?.children[0]?.children ?? [])
    .filter((node) => node.tagClass === 'universal' && node.tagNumber === DerTag.SEQUENCE)
    .map((node) => node.raw)

  const tbsFields = asSequence(tbs)
  // ResponseData ::= SEQUENCE { version [0]?, responderID, producedAt,
  //                             responses, responseExtensions [1]? }
  const versioned = tbsFields[0]?.tagClass === 'context' && tbsFields[0].tagNumber === 0
  const producedAtNode = tbsFields[versioned ? 2 : 1]
  const responsesNode = tbsFields[versioned ? 3 : 2]
  if (producedAtNode === undefined || responsesNode === undefined) {
    throw new DerParseError(0, 'ResponseData yapısı eksik.')
  }

  // `responseExtensions` [1] EXPLICIT, `responses`TAN SONRA gelir. Etiket
  // numarasına göre aramak yetmez: `responderID` seçeneği de `byName [1]`
  // olabilir ve o zaman yanlış düğüm bulunur.
  const nonce = readNonce(tbsFields.slice(versioned ? 4 : 3))
  return {
    tbsBytes: tbs.raw,
    producedAt: asTime(producedAtNode),
    certificates,
    signatureAlgorithmOid: asOid(asSequence(algorithmNode)[0] ?? algorithmNode),
    signature: asBitString(signatureNode),
    responses: asSequence(responsesNode).map(parseSingleResponse),
    ...(nonce === undefined ? {} : { nonce }),
    der: bytes,
  }
}

/**
 * `responseExtensions` içindeki nonce değerini okur.
 *
 * @param trailing - `responses` alanından SONRAKİ düğümler
 */
const readNonce = (trailing: readonly DerNode[]): Uint8Array | undefined => {
  const extensions = findContext(trailing, 1)?.children[0]
  if (extensions === undefined) return undefined
  for (const extension of asSequence(extensions)) {
    const parts = asSequence(extension)
    const oidNode = parts[0]
    const valueNode = parts[parts.length - 1]
    if (oidNode === undefined || valueNode === undefined) continue
    if (asOid(oidNode) !== OID.NONCE) continue
    // extnValue bir OCTET STRING; içindeki değer de OCTET STRING olarak sarılı.
    try {
      return asOctetString(decodeDer(valueNode.content))
    } catch {
      return valueNode.content
    }
  }
  return undefined
}

/** Tek bir `SingleResponse` çözümler. */
const parseSingleResponse = (node: DerNode): SingleOcspResponse => {
  const fields = asSequence(node)
  const certIdNode = fields[0]
  const statusNode = fields[1]
  const thisUpdateNode = fields[2]
  if (certIdNode === undefined || statusNode === undefined || thisUpdateNode === undefined) {
    throw new DerParseError(0, 'SingleResponse yapısı eksik.')
  }

  const certIdFields = asSequence(certIdNode)
  const algorithmNode = certIdFields[0]
  const nameHashNode = certIdFields[1]
  const keyHashNode = certIdFields[2]
  const serialNode = certIdFields[3]
  if (
    algorithmNode === undefined ||
    nameHashNode === undefined ||
    keyHashNode === undefined ||
    serialNode === undefined
  ) {
    throw new DerParseError(0, 'CertID yapısı eksik.')
  }
  const hashOid = asOid(asSequence(algorithmNode)[0] ?? algorithmNode)
  const hashAlgorithm = DIGEST_NAME[hashOid]
  if (hashAlgorithm === undefined) {
    throw new DerParseError(0, `Desteklenmeyen CertID özeti: ${hashOid}`)
  }

  // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT
  //                         RevokedInfo, unknown [2] IMPLICIT UnknownInfo }
  let status: CertificateStatus
  if (statusNode.tagNumber === 0) {
    status = { status: 'good' }
  } else if (statusNode.tagNumber === 1) {
    const revoked = statusNode.children[0]
    const reasonNode = findContext(statusNode.children, 0)
    const reasonCode = reasonNode?.children[0]?.content[0]
    status = {
      status: 'revoked',
      revokedAt: revoked === undefined ? new Date(0) : asTime(revoked),
      // `revocationReason [0] EXPLICIT CRLReason` — EXPLICIT olduğu için
      // değer, sarmalayıcının İÇİNDEKİ ENUMERATED'da. Doğrudan
      // `reasonNode.content[0]` okumak ENUMERATED'ın ETİKET baytını
      // (0x0a = 10) değer sanmak olur.
      ...(reasonCode === undefined ? {} : { reason: reasonCode }),
    }
  } else {
    status = { status: 'unknown' }
  }

  const nextUpdate = findContext(fields.slice(3), 0)?.children[0]
  return {
    certId: {
      hashAlgorithm,
      issuerNameHash: asOctetString(nameHashNode),
      issuerKeyHash: asOctetString(keyHashNode),
      serialNumber: asInteger(serialNode),
    },
    status,
    thisUpdate: asTime(thisUpdateNode),
    ...(nextUpdate === undefined ? {} : { nextUpdate: asTime(nextUpdate) }),
  }
}

/** {@link verifyOcspResponse} seçenekleri. */
export interface VerifyOcspOptions {
  /** Durumu sorulan sertifika (DER). */
  readonly certificate: Uint8Array
  /** Onu düzenleyen sertifika (DER) — yanıtı imzalayan da genelde budur. */
  readonly issuer: Uint8Array
  /** İstekte gönderilen tek kullanımlık değer; verilirse eşitliği denetlenir. */
  readonly nonce?: Uint8Array
  /** Tazelik denetiminde kullanılacak an; varsayılan şimdi. */
  readonly at?: Date
}

/** {@link verifyOcspResponse} sonucu. */
export type OcspVerification =
  | {
      readonly valid: true
      /** Sertifikanın iptal durumu. */
      readonly certificateStatus: CertificateStatus
      readonly thisUpdate: Date
      readonly nextUpdate?: Date
      /** Yanıtı imzalayan sertifika (DER). */
      readonly responderCertificate: Uint8Array
    }
  | { readonly valid: false; readonly reason: string }

/**
 * OCSP yanıtını doğrular.
 *
 * Dört bağ denetlenir:
 * 1. Yanıt, **sorulan sertifikaya** ait (`CertID` yeniden hesaplanır),
 * 2. Yanıtın imzası, yanıtlayıcının sertifikasıyla doğrulanıyor,
 * 3. `nonce` verilmişse yanıttaki değerle aynı,
 * 4. Yanıt tazelik penceresi içinde (`thisUpdate` ≤ an ≤ `nextUpdate`).
 *
 * **Denetlenmeyen:** yanıtlayıcının bu sertifikayı yanıtlamaya YETKİLİ
 * olup olmadığı (`id-kp-OCSPSigning` genişletilmiş anahtar kullanımı ya da
 * düzenleyenin kendisi olması) ve zincirin güvenilirliği. Zincir
 * doğrulaması bu kütüphanenin kapsamı dışında.
 *
 * @param response - {@link parseOcspResponse} çıktısı
 * @param options - {@link VerifyOcspOptions}
 * @returns Doğrulama sonucu; geçersizlik hata değil, sonuçtur
 */
export const verifyOcspResponse = (
  response: OcspResponse,
  options: VerifyOcspOptions,
): OcspVerification => {
  const single = response.responses[0]
  if (single === undefined) return { valid: false, reason: 'Yanıtta hiç sertifika durumu yok.' }

  // 1. Yanıt gerçekten SORULAN sertifikaya mı ait.
  const expected = computeCertId(options.certificate, options.issuer, single.certId.hashAlgorithm)
  if (
    expected.serialNumber !== single.certId.serialNumber ||
    !timingSafeEqual(expected.issuerNameHash, single.certId.issuerNameHash) ||
    !timingSafeEqual(expected.issuerKeyHash, single.certId.issuerKeyHash)
  ) {
    return { valid: false, reason: 'Yanıt başka bir sertifikaya ait — CertID eşleşmiyor.' }
  }

  // 2. İmza.
  const responderDer = response.certificates[0] ?? options.issuer
  const hash = SIGNATURE_HASH[response.signatureAlgorithmOid]
  if (hash === undefined) {
    return {
      valid: false,
      reason: `Desteklenmeyen imza algoritması: ${response.signatureAlgorithmOid}`,
    }
  }
  try {
    const responder = new X509Certificate(Buffer.from(responderDer))
    const verifier = createVerify(hash)
    verifier.update(Buffer.from(response.tbsBytes))
    if (!verifier.verify(responder.publicKey, Buffer.from(response.signature))) {
      return { valid: false, reason: 'OCSP yanıtının imzası doğrulanmadı.' }
    }
  } catch (error) {
    return {
      valid: false,
      reason: `OCSP imzası değerlendirilemedi: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  // 3. Tekrar oynatma.
  if (options.nonce !== undefined) {
    if (response.nonce === undefined) {
      return {
        valid: false,
        reason: 'Yanıtta tek kullanımlık değer yok — tekrar oynatılmış olabilir.',
      }
    }
    if (!timingSafeEqual(response.nonce, options.nonce)) {
      return { valid: false, reason: 'Yanıttaki tek kullanımlık değer istektekiyle aynı değil.' }
    }
  }

  // 4. Tazelik. `nextUpdate` yoksa yanıt her zaman güncel sayılır (RFC 6960
  // §4.2.2.1) — ama geçmiş bir `thisUpdate` yine de anlamlıdır.
  const at = options.at ?? new Date()
  if (single.thisUpdate.getTime() > at.getTime() + 60_000) {
    return { valid: false, reason: 'Yanıtın geçerlilik başlangıcı gelecekte.' }
  }
  if (single.nextUpdate !== undefined && single.nextUpdate.getTime() < at.getTime()) {
    return { valid: false, reason: 'Yanıtın geçerlilik süresi dolmuş.' }
  }

  return {
    valid: true,
    certificateStatus: single.status,
    thisUpdate: single.thisUpdate,
    ...(single.nextUpdate === undefined ? {} : { nextUpdate: single.nextUpdate }),
    responderCertificate: responderDer,
  }
}
