import { createHash } from 'node:crypto'

import { SigningError } from '../core/errors.js'
import { buildTimestampRequest, verifyTimestampToken } from '../pki/tsp.js'

import { addDocumentSecurityStore, type ValidationMaterial } from './dss.js'
import { DEFAULT_SIGNATURE_SPACE, placeSignatureField } from './placement.js'

/**
 * PAdES seviye yükseltmeleri — B-LT ve B-LTA (ETSI EN 319 142-1 §5.4, 5.5).
 *
 * İki adım, iki artımlı güncelleme:
 *
 * - **B-LT**: doğrulama malzemesi (zincir + iptal kanıtı) belgeye DSS olarak
 *   eklenir. Kriptografi yok, yalnızca belgeye veri konur.
 * - **B-LTA**: belgenin tamamının üstüne bir `/DocTimeStamp` atılır. LT
 *   verisini de kapsar; kapsamasının nedeni şu: gömdüğünüz OCSP yanıtını
 *   imzalayan sertifikanın da bir gün süresi dolar, damga o zinciri
 *   kırılmadan uzatır.
 *
 * İkisi ayrı güncelleme olarak yazılıyor çünkü spesifikasyon akışı bu:
 * önce LT, sonra üstüne damga. Tek güncellemede birleştirmek, damganın
 * kendi DSS'ini kapsamasını da imkânsız kılardı.
 */

/** {@link padesUpgrade} — B-LT seçenekleri. */
export interface PadesUpgradeToLongTerm extends ValidationMaterial {
  readonly pdf: Uint8Array
  readonly to: 'LT'
  /**
   * `/VRI` sözlüğüne yazılacak zaman (`/TU`). Verilmezse şimdiki zaman;
   * `null` verilirse hiç yazılmaz — çıktının belirlenimci olması istenirse.
   */
  readonly vriTime?: Date | null
}

/**
 * İmzalı PDF'i B-LT seviyesine yükseltir.
 *
 * @param options - {@link PadesUpgradeToLongTerm}
 * @returns DSS eklenmiş PDF
 * @throws {SigningError} Belgede imza yoksa ya da hiç malzeme verilmezse
 *
 * @example
 * ```ts
 * const lt = padesUpgrade({
 *   pdf: imzali,
 *   to: 'LT',
 *   certificates: [araCa, kokCa],
 *   ocspResponses: [ocspYaniti],
 * })
 * ```
 */
export const padesUpgrade = (options: PadesUpgradeToLongTerm): Uint8Array =>
  addDocumentSecurityStore(
    options.pdf,
    {
      ...(options.certificates === undefined ? {} : { certificates: options.certificates }),
      ...(options.ocspResponses === undefined ? {} : { ocspResponses: options.ocspResponses }),
      ...(options.crls === undefined ? {} : { crls: options.crls }),
    },
    options.vriTime === undefined ? {} : { vriTime: options.vriTime },
  )

/** {@link padesDocumentTimestamp} seçenekleri. */
export interface PadesDocumentTimestampOptions {
  /** Damgalanacak PDF — normalde B-LT seviyesine getirilmiş olan. */
  readonly pdf: Uint8Array
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digestAlgorithm?: 'sha256' | 'sha384' | 'sha512'
  /** TSA'dan istenen politika OID'i. */
  readonly policyOid?: string
  /** Tekrar saldırılarına karşı tek kullanımlık sayı. */
  readonly nonce?: bigint
  /** TSA sertifikası jetona gömülsün mü; varsayılan `true`. */
  readonly requestCertificate?: boolean
  /**
   * Jeton için ayrılacak yer (onaltılık karakter). Varsayılan 16384.
   *
   * İmzada olduğu gibi: yer ayrılmadan `/ByteRange` hesaplanamaz,
   * `/ByteRange` olmadan damgalanacak baytlar belli olmaz.
   */
  readonly signatureSpace?: number
}

/** Jetonu beklenen belge zaman damgası. */
export interface PendingDocumentTimestamp {
  /** TSA'ya `application/timestamp-query` olarak gönderilecek istek. */
  readonly request: Uint8Array
  /** Damgalanan baytların özeti — istekteki `messageImprint`. */
  readonly messageImprint: Uint8Array
  /** Damgalanan baytlar; jetonu kendiniz doğrulamak isterseniz. */
  readonly stampedBytes: Uint8Array
  /**
   * Jetonu `/Contents`e koyar ve B-LTA seviyesindeki PDF'i döndürür.
   *
   * Jetonun gerçekten BU baytları damgaladığı önce denetlenir; denetim
   * `verifyToken: false` ile kapatılabilir ama kapatmak, yanlış belgeye ait
   * bir jetonu gömüp sessizce geçersiz bir B-LTA üretmenin en olası yolu.
   *
   * @throws {SigningError} Jeton bu baytları damgalamıyorsa ya da sığmazsa
   */
  readonly finish: (token: Uint8Array, options?: { readonly verifyToken?: boolean }) => Uint8Array
}

/**
 * Belge zaman damgası (`/DocTimeStamp`) yerleştirir — PAdES B-LTA.
 *
 * Damga, PDF açısından imzalayanı olmayan bir imzadır: `/Contents` içinde
 * ham bir RFC 3161 jetonu durur, `/SubFilter /ETSI.RFC3161` bunu söyler.
 * `/M` YAZILMAZ — zaman, jetonun içindeki TSA'nın söylediğidir; sözlüğe
 * ikinci bir zaman koymak, çelişebilecek iki kaynak yaratırdı.
 *
 * @param options - {@link PadesDocumentTimestampOptions}
 * @returns Jetonu bekleyen damga
 *
 * @example
 * ```ts
 * const bekleyen = padesDocumentTimestamp({ pdf: lt })
 * const yanit = await fetch(tsaUrl, {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/timestamp-query' },
 *   body: bekleyen.request,
 * })
 * const lta = bekleyen.finish(parseTimestampResponse(new Uint8Array(await yanit.arrayBuffer())))
 * ```
 */
export const padesDocumentTimestamp = (
  options: PadesDocumentTimestampOptions,
): PendingDocumentTimestamp => {
  const algorithm = options.digestAlgorithm ?? 'sha256'
  const placed = placeSignatureField({
    pdf: options.pdf,
    space: options.signatureSpace ?? DEFAULT_SIGNATURE_SPACE,
    dictionary: '/Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161',
    fieldPrefix: 'Damga',
  })

  const messageImprint = new Uint8Array(createHash(algorithm).update(placed.signedBytes).digest())
  const request = buildTimestampRequest({
    messageImprint,
    hashAlgorithm: algorithm,
    ...(options.policyOid === undefined ? {} : { policyOid: options.policyOid }),
    ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    ...(options.requestCertificate === undefined
      ? {}
      : { requestCertificate: options.requestCertificate }),
  })

  return {
    request,
    messageImprint,
    stampedBytes: placed.signedBytes,
    finish: (token, finishOptions = {}): Uint8Array => {
      if (finishOptions.verifyToken !== false) {
        const outcome = verifyTimestampToken(token, {
          data: placed.signedBytes,
          ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
        })
        if (!outcome.valid) {
          throw new SigningError(`Belge zaman damgası bu belgeyi damgalamıyor: ${outcome.reason}`)
        }
      }
      return placed.finish(token)
    },
  }
}
