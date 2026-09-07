import { createHash } from 'node:crypto'

import {
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asTime,
  decodeDer,
  derBoolean,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
} from '../asn1/der.js'
import { timingSafeEqual } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

import { parseCmsSignedData, verifyCmsSigner, type CmsSignedData } from './cms.js'

/**
 * RFC 3161 zaman damgası protokolü — istek üretme, yanıt çözme, jeton
 * doğrulama.
 *
 * Zaman damgası jetonu (`TimeStampToken`) bir CMS `SignedData`'dır ve
 * sarmaladığı içerik `TSTInfo`'dur. Yani bu modül tamamen
 * {@link ./cms.js | CMS katmanının} üstünde duruyor; CAdES eklendiğinde
 * aynı çekirdek yeniden kullanılacak.
 *
 * Ağ isteği bu modülde **yoktur**. `buildTimestampRequest` baytları üretir,
 * `parseTimestampResponse` baytları okur; aradaki HTTP çağrısını çağıran
 * yapar. Kütüphanenin kendiliğinden ağa çıkmaması bilinçli: bir imza
 * kütüphanesinin ne zaman ve nereye bağlandığı çağıranın kararı olmalı.
 */

/** RFC 3161 nesne tanımlayıcıları. */
export const TspOid = {
  /** `id-ct-TSTInfo`. */
  TST_INFO: '1.2.840.113549.1.9.16.1.4',
} as const

/** Desteklenen özet algoritmaları → OID. */
const DIGEST_OID: Readonly<Record<string, string>> = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

/** OID → `node:crypto` özet adı. */
const DIGEST_NAME: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(DIGEST_OID).map(([name, oid]) => [oid, name]),
)

/** {@link buildTimestampRequest} seçenekleri. */
export interface TimestampRequestOptions {
  /** Damgalanacak verinin özeti. */
  readonly messageImprint: Uint8Array
  /** Özeti üreten algoritma; varsayılan `sha256`. */
  readonly hashAlgorithm?: 'sha256' | 'sha384' | 'sha512'
  /**
   * TSA'dan istenen politika OID'i. Verilmezse TSA kendi varsayılanını
   * kullanır.
   */
  readonly policyOid?: string
  /**
   * Tekrar saldırılarına karşı tek kullanımlık sayı.
   *
   * Verilmezse üretilmez. Üretmek isterseniz kriptografik olarak rastgele
   * olmalı ve yanıtta AYNI değerin döndüğü denetlenmeli — bu denetim
   * {@link verifyTimestampToken} içinde yapılıyor.
   */
  readonly nonce?: bigint
  /**
   * TSA sertifikasını yanıta gömsün mü. Varsayılan `true`.
   *
   * Gömülmezse jeton kendi başına doğrulanamaz; sertifikayı başka bir
   * yerden bulmak gerekir. Arşivlenecek bir imzada bu neredeyse her zaman
   * istenmeyen bir durum.
   */
  readonly requestCertificate?: boolean
}

/**
 * RFC 3161 `TimeStampReq` üretir.
 *
 * @param options - {@link TimestampRequestOptions}
 * @returns İstek DER kodlaması — TSA'ya `application/timestamp-query` olarak gönderilir
 *
 * @example
 * ```ts
 * const istek = buildTimestampRequest({ messageImprint: digest('SHA-256', veri) })
 * const yanit = await fetch(tsaUrl, {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/timestamp-query' },
 *   body: istek,
 * })
 * const jeton = parseTimestampResponse(new Uint8Array(await yanit.arrayBuffer()))
 * ```
 */
export const buildTimestampRequest = (options: TimestampRequestOptions): Uint8Array => {
  const hash = options.hashAlgorithm ?? 'sha256'
  const oid = DIGEST_OID[hash]
  if (oid === undefined) throw new RangeError(`Desteklenmeyen özet algoritması: ${hash}`)

  const expected = { sha256: 32, sha384: 48, sha512: 64 }[hash]
  if (options.messageImprint.length !== expected) {
    throw new RangeError(
      `${hash} özeti ${String(expected)} bayt olmalı; ${String(options.messageImprint.length)} verildi.`,
    )
  }

  // TimeStampReq ::= SEQUENCE { version, messageImprint, reqPolicy?,
  //                             nonce?, certReq DEFAULT FALSE, extensions? }
  return derSequence(
    derInteger(1n),
    derSequence(derSequence(derOid(oid), derNull()), derOctetString(options.messageImprint)),
    ...(options.policyOid === undefined ? [] : [derOid(options.policyOid)]),
    ...(options.nonce === undefined ? [] : [derInteger(options.nonce)]),
    // `certReq` DEFAULT FALSE; DER varsayılan değeri yazmaz.
    ...((options.requestCertificate ?? true) ? [derBoolean(true)] : []),
  )
}

/** RFC 3161 `PKIStatus` değerleri. */
const STATUS_TEXT: Readonly<Record<number, string>> = {
  0: 'kabul edildi',
  1: 'değişikliklerle kabul edildi',
  2: 'reddedildi',
  3: 'bekliyor',
  4: 'uyarı — iptal bekleniyor',
  5: 'iptal edildi',
}

/**
 * TSA yanıtından zaman damgası jetonunu çıkarır.
 *
 * @param bytes - `TimeStampResp` DER kodlaması
 * @returns Jetonun (CMS `ContentInfo`) DER kodlaması
 * @throws {DerParseError} TSA isteği reddettiyse ya da yapı bozuksa
 */
export const parseTimestampResponse = (bytes: Uint8Array): Uint8Array => {
  const fields = asSequence(decodeDer(bytes))
  const statusInfo = fields[0]
  if (statusInfo === undefined) throw new DerParseError(0, 'PKIStatusInfo yok.')
  const status = Number(asInteger(asSequence(statusInfo)[0] ?? statusInfo))

  const token = fields[1]
  // 0 ve 1 kabul; gerisi ret. Reddi sessizce geçmek, jetonsuz bir "T
  // seviyesi" imza üretmek olurdu.
  if (status !== 0 && status !== 1) {
    throw new DerParseError(
      0,
      `TSA isteği reddetti (durum ${String(status)}: ${STATUS_TEXT[status] ?? 'bilinmiyor'}).`,
    )
  }
  if (token === undefined) throw new DerParseError(0, 'TSA kabul etti ama jeton göndermedi.')
  return token.raw
}

/** Çözümlenmiş `TSTInfo`. */
export interface TstInfo {
  /** TSA'nın uyguladığı politika OID'i. */
  readonly policyOid: string
  /** Damgalanan verinin özeti. */
  readonly messageImprint: Uint8Array
  /** Özet algoritması (`node:crypto` adı). */
  readonly hashAlgorithm: string
  /** Jeton seri numarası. */
  readonly serialNumber: bigint
  /** TSA'nın bildirdiği zaman. */
  readonly genTime: Date
  /** İstekte gönderilmişse tek kullanımlık sayı. */
  readonly nonce?: bigint
}

/**
 * `TSTInfo` yapısını çözümler.
 *
 * @param bytes - `TSTInfo` DER kodlaması (jetonun sarmaladığı içerik)
 * @returns Çözümlenmiş bilgi
 */
export const parseTstInfo = (bytes: Uint8Array): TstInfo => {
  const fields = asSequence(decodeDer(bytes))
  const policyNode = fields[1]
  const imprintNode = fields[2]
  const serialNode = fields[3]
  const genTimeNode = fields[4]
  if (
    policyNode === undefined ||
    imprintNode === undefined ||
    serialNode === undefined ||
    genTimeNode === undefined
  ) {
    throw new DerParseError(0, 'TSTInfo yapısı eksik.')
  }

  const imprint = asSequence(imprintNode)
  const algorithmNode = imprint[0]
  const hashedNode = imprint[1]
  if (algorithmNode === undefined || hashedNode === undefined) {
    throw new DerParseError(0, 'messageImprint yapısı eksik.')
  }
  const hashOid = asOid(asSequence(algorithmNode)[0] ?? algorithmNode)
  const hashAlgorithm = DIGEST_NAME[hashOid]
  if (hashAlgorithm === undefined) {
    throw new DerParseError(0, `Desteklenmeyen özet algoritması: ${hashOid}`)
  }

  // `nonce` isteğe bağlı ve `accuracy`/`ordering` alanlarından sonra gelir;
  // türüne göre aranır çünkü konumu sabit değil.
  const nonceNode = fields
    .slice(5)
    .find((node) => node.tagClass === 'universal' && node.tagNumber === 2)

  return {
    policyOid: asOid(policyNode),
    messageImprint: asOctetString(hashedNode),
    hashAlgorithm,
    serialNumber: asInteger(serialNode),
    genTime: asTime(genTimeNode),
    ...(nonceNode === undefined ? {} : { nonce: asInteger(nonceNode) }),
  }
}

/** {@link verifyTimestampToken} seçenekleri. */
export interface VerifyTimestampOptions {
  /**
   * Damgalandığı iddia edilen veri.
   *
   * Verilirse özeti hesaplanır ve jetondaki `messageImprint` ile
   * karşılaştırılır. **Verilmezse bu bağ hiç kurulmaz** — jeton
   * kriptografik olarak geçerli olur ama neyi damgaladığı bilinmez.
   */
  readonly data?: Uint8Array
  /** İstekte gönderilen tek kullanımlık sayı; verilirse eşitliği denetlenir. */
  readonly nonce?: bigint
}

/** {@link verifyTimestampToken} sonucu. */
export type TimestampVerification =
  | {
      readonly valid: true
      readonly info: TstInfo
      /** Jetonu imzalayan TSA sertifikası (DER). */
      readonly certificate: Uint8Array
      /** Jetonun CMS yapısı — ileri düzey inceleme için. */
      readonly signedData: CmsSignedData
    }
  | { readonly valid: false; readonly reason: string }

/**
 * Zaman damgası jetonunu doğrular.
 *
 * Dört bağ denetlenir:
 * 1. Jeton bir CMS `SignedData` ve sarmaladığı içerik `TSTInfo`,
 * 2. CMS imzası, gömülü TSA sertifikasıyla doğrulanıyor,
 * 3. `data` verilmişse, özeti jetondaki `messageImprint` ile eşleşiyor,
 * 4. `nonce` verilmişse, jetondaki değerle aynı.
 *
 * **Denetlenmeyen:** TSA sertifikasının güvenilir olup olmadığı ve
 * `timeStamping` genişletilmiş anahtar kullanımı taşıyıp taşımadığı. Zincir
 * doğrulaması bu kütüphanenin kapsamı dışında; kendi güven kümenizle
 * yapmalısınız. Aksi hâlde herkes kendi TSA'sını kurup istediği zamanı
 * damgalayabilir.
 *
 * @param token - Jetonun (CMS `ContentInfo`) DER kodlaması
 * @param options - {@link VerifyTimestampOptions}
 * @returns Doğrulama sonucu; geçersizlik hata değil, sonuçtur
 */
export const verifyTimestampToken = (
  token: Uint8Array,
  options: VerifyTimestampOptions = {},
): TimestampVerification => {
  let signedData: CmsSignedData
  try {
    signedData = parseCmsSignedData(token)
  } catch (error) {
    return {
      valid: false,
      reason: `Jeton CMS olarak okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  if (signedData.contentType !== TspOid.TST_INFO) {
    return {
      valid: false,
      reason: `Jetonun içeriği TSTInfo değil: ${signedData.contentType}`,
    }
  }
  if (signedData.content === undefined) {
    return { valid: false, reason: 'Jetonda TSTInfo içeriği yok.' }
  }

  const signer = signedData.signerInfos[0]
  if (signer === undefined) return { valid: false, reason: 'Jetonda imzacı yok.' }

  const cms = verifyCmsSigner(signedData, signer)
  if (!cms.valid) return { valid: false, reason: cms.reason }

  let info: TstInfo
  try {
    info = parseTstInfo(signedData.content)
  } catch (error) {
    return {
      valid: false,
      reason: `TSTInfo okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    }
  }

  if (options.data !== undefined) {
    const actual = new Uint8Array(
      createHash(info.hashAlgorithm).update(Buffer.from(options.data)).digest(),
    )
    if (!timingSafeEqual(actual, info.messageImprint)) {
      return { valid: false, reason: 'Jeton başka bir veriyi damgalamış — özet eşleşmiyor.' }
    }
  }

  if (options.nonce !== undefined && info.nonce !== options.nonce) {
    return {
      valid: false,
      reason:
        info.nonce === undefined
          ? 'Jetonda tek kullanımlık sayı yok — yanıt tekrar oynatılmış olabilir.'
          : 'Jetondaki tek kullanımlık sayı istektekiyle aynı değil.',
    }
  }

  return { valid: true, info, certificate: cms.certificate, signedData }
}
