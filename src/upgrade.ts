import { randomUUID } from 'node:crypto'

import {
  c14nAlgorithmFromUri,
  C14N_URI,
  canonicalizeToBytes,
  type C14nAlgorithm,
} from './c14n/canonicalize.js'
import { toBase64, wrapBase64 } from './core/bytes.js'
import { SigningError } from './core/errors.js'
import { buildTimestampRequest, verifyTimestampToken } from './pki/tsp.js'
import { DIGEST_NODE_NAME, Namespace, type DigestAlgorithm } from './xades/constants.js'
import { attribute, ds, xades } from './xades/element.js'
import { digest } from './xades/signature.js'
import { replaceElement } from './xml/edit.js'
import {
  childNamed,
  getAttributeValue,
  walkElements,
  type XmlDocument,
  type XmlElement,
} from './xml/node.js'
import { parseXml } from './xml/parse.js'
import { serializeXml } from './xml/serialize.js'

/**
 * XAdES seviye yükseltme.
 *
 * Şu an yalnızca **T** (zaman damgası) destekleniyor. LT ve LTA — sertifika
 * ve iptal verisinin gömülmesi — yol haritasında.
 *
 * ## Neden imzayı bozmuyor
 *
 * Zaman damgası `xades:UnsignedProperties` altına yazılır ve o alt ağaç
 * **hiçbir `ds:Reference` tarafından kapsanmaz**. Adı da bunu söylüyor:
 * imzalanmamış özellikler. Belgeye imzadan SONRA eklenebilmelerinin tek
 * nedeni budur; `SignedProperties`e bir şey eklemek imzayı anında geçersiz
 * kılardı.
 *
 * ## Ağ isteği yok
 *
 * Bu modül TSA'ya bağlanmaz. {@link timestampRequest} istek baytlarını
 * üretir, aradaki HTTP çağrısını çağıran yapar, {@link upgrade} dönen
 * jetonu yerleştirir. Bir imza kütüphanesinin ne zaman ve nereye
 * bağlandığı çağıranın kararı olmalı — hem güvenlik hem de bu akışın
 * çoğu zaman bir kuyruk ya da yeniden deneme mantığı gerektirmesi
 * nedeniyle.
 */

/** {@link timestampRequest} ve {@link upgrade} için ortak seçenekler. */
export interface TimestampTarget {
  /** İmzalanmış belge. */
  readonly xml: string | XmlDocument
  /**
   * Damgalanacak imzanın kimliği. Belgede tek imza varsa gerekmez.
   */
  readonly signatureId?: string
  /**
   * `ds:SignatureValue` öğesini kanonikleştirmede kullanılacak algoritma.
   *
   * Verilmezse imzanın kendi `ds:CanonicalizationMethod` değeri kullanılır.
   * Bu varsayılan bilinçli: iki farklı algoritma kullanmak, jetonu üreten
   * ile doğrulayanın farklı baytlar üzerinde çalışmasına yol açan en
   * kolay yol.
   */
  readonly canonicalization?: C14nAlgorithm
  /** Özet algoritması; varsayılan `SHA-256`. */
  readonly digestAlgorithm?: DigestAlgorithm
}

/** {@link timestampRequest} seçenekleri. */
export interface TimestampRequestInput extends TimestampTarget {
  /** TSA'dan istenen politika OID'i. */
  readonly policyOid?: string
  /** Tekrar saldırısına karşı tek kullanımlık sayı. */
  readonly nonce?: bigint
  /** TSA sertifikası jetona gömülsün mü; varsayılan `true`. */
  readonly requestCertificate?: boolean
}

/**
 * İmza için RFC 3161 zaman damgası isteği üretir.
 *
 * Damgalanan şey, ETSI TS 101 903 §7.3 uyarınca **kanonikleştirilmiş
 * `ds:SignatureValue` öğesidir** — öğenin kendisi, etiketleri dâhil;
 * yalnızca içindeki base64 metin değil. Bu ayrımı kaçırmak, kendi
 * doğrulayıcınız dışında hiçbir yerde kabul edilmeyen bir jeton üretir.
 *
 * @param options - {@link TimestampRequestInput}
 * @returns `TimeStampReq` DER kodlaması
 * @throws {SigningError} İmza bulunamazsa
 *
 * @example
 * ```ts
 * const istek = timestampRequest({ xml: imzali })
 * const yanit = await fetch('http://tzd.kamusm.gov.tr', {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/timestamp-query' },
 *   body: istek,
 * })
 * const jeton = parseTimestampResponse(new Uint8Array(await yanit.arrayBuffer()))
 * const yukseltilmis = upgrade({ xml: imzali, to: 'T', token: jeton })
 * ```
 */
export const timestampRequest = (options: TimestampRequestInput): Uint8Array => {
  const { imprint, digestAlgorithm } = signatureValueImprint(options)
  return buildTimestampRequest({
    messageImprint: imprint,
    hashAlgorithm: DIGEST_NODE_NAME[digestAlgorithm] as 'sha256' | 'sha384' | 'sha512',
    ...(options.policyOid === undefined ? {} : { policyOid: options.policyOid }),
    ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
    ...(options.requestCertificate === undefined
      ? {}
      : { requestCertificate: options.requestCertificate }),
  })
}

/** {@link upgrade} seçenekleri. */
export interface UpgradeOptions extends TimestampTarget {
  /** Hedef seviye. Şu an yalnızca `'T'`. */
  readonly to: 'T'
  /** TSA'dan alınan zaman damgası jetonu (CMS `ContentInfo` DER'i). */
  readonly token: Uint8Array
  /**
   * Jetonun gerçekten bu imzayı damgaladığı doğrulansın mı. Varsayılan `true`.
   *
   * Kapatmak yalnızca jetonun doğrulanamadığı ama yine de saklanmak
   * istendiği kenar durumlar içindir. Açık bırakmak, yanlış imzaya ait bir
   * jetonu belgeye gömmeyi imkânsız kılar — sessizce yanlış bir "T
   * seviyesi" imza üretmenin en olası yolu bu.
   */
  readonly verifyToken?: boolean
  /** `xades:SignatureTimeStamp` öğesinin kimliği; verilmezse üretilir. */
  readonly timestampId?: string
}

/**
 * İmzayı zaman damgasıyla T seviyesine yükseltir.
 *
 * @param options - {@link UpgradeOptions}
 * @returns Yükseltilmiş belge (XML metni)
 * @throws {SigningError} İmza bulunamazsa ya da jeton bu imzayı damgalamıyorsa
 */
export const upgrade = (options: UpgradeOptions): string => {
  const { document, signature, imprint } = locateSignature(options)

  if (options.verifyToken ?? true) {
    const sonuc = verifyTimestampToken(options.token)
    if (!sonuc.valid) {
      throw new SigningError(`Zaman damgası jetonu doğrulanamadı: ${sonuc.reason}`)
    }
    // Jetonun BU imzayı damgaladığını bağla. Bağlamadan gömmek, başka bir
    // belgeye ait geçerli bir jetonu buraya taşımaya izin verirdi.
    if (Buffer.from(sonuc.info.messageImprint).compare(Buffer.from(imprint)) !== 0) {
      throw new SigningError(
        'Jeton bu imzayı damgalamamış — messageImprint eşleşmiyor. ' +
          'İsteği üreten belge ile yükseltilen belge aynı olmalı.',
      )
    }
  }

  const canonicalization = resolveCanonicalization(options, signature)
  const timestamp = xades(
    'SignatureTimeStamp',
    [
      ds('CanonicalizationMethod', [], [attribute('Algorithm', C14N_URI[canonicalization])]),
      xades('EncapsulatedTimeStamp', [
        { kind: 'text', value: wrapBase64(toBase64(options.token)) },
      ]),
    ],
    [attribute('Id', options.timestampId ?? `TimeStamp-${randomUUID()}`)],
  )

  return serializeXml(insertUnsignedProperty(document, signature, timestamp))
}

/**
 * `xades:UnsignedSignatureProperties` altına bir öğe ekler; yoksa gerekli
 * kapsayıcıları oluşturur.
 *
 * ETSI şemasında `UnsignedProperties`, `QualifyingProperties` içinde
 * `SignedProperties`ten SONRA gelir — sıra `xsd:sequence` olduğu için
 * bağlayıcı.
 */
const insertUnsignedProperty = (
  document: XmlDocument,
  signature: XmlElement,
  property: XmlElement,
): XmlDocument => {
  const qualifying = findIn(signature, Namespace.XADES, 'QualifyingProperties')
  if (qualifying === undefined) {
    throw new SigningError(
      'İmzada xades:QualifyingProperties yok; yalnızca XAdES imzaları yükseltilebilir.',
    )
  }

  const unsigned = childNamed(qualifying, Namespace.XADES, 'UnsignedProperties')
  if (unsigned === undefined) {
    return replaceElement(document, qualifying, {
      ...qualifying,
      children: [
        ...qualifying.children,
        xades('UnsignedProperties', [xades('UnsignedSignatureProperties', [property])]),
      ],
    })
  }

  const unsignedSignature = childNamed(unsigned, Namespace.XADES, 'UnsignedSignatureProperties')
  if (unsignedSignature === undefined) {
    return replaceElement(document, unsigned, {
      ...unsigned,
      children: [...unsigned.children, xades('UnsignedSignatureProperties', [property])],
    })
  }

  // Birden çok zaman damgası geçerlidir — her biri bir öncekinin üstüne
  // eklenir ve hepsi aynı `ds:SignatureValue`yu damgalar.
  return replaceElement(document, unsignedSignature, {
    ...unsignedSignature,
    children: [...unsignedSignature.children, property],
  })
}

/** Hedef imzayı ve damgalanacak özeti bulur. */
const locateSignature = (
  options: TimestampTarget,
): { document: XmlDocument; signature: XmlElement; imprint: Uint8Array } => {
  const document = typeof options.xml === 'string' ? parseXml(options.xml) : options.xml
  const signatures = [...walkElements(document.root)].filter(
    (element) => element.namespace === Namespace.SIGNATURE && element.localName === 'Signature',
  )

  const signature =
    options.signatureId === undefined
      ? signatures[0]
      : signatures.find((element) => getAttributeValue(element, 'Id') === options.signatureId)
  if (signature === undefined) {
    throw new SigningError(
      options.signatureId === undefined
        ? 'Belgede ds:Signature öğesi yok.'
        : `"${options.signatureId}" kimlikli imza bulunamadı.`,
    )
  }
  if (options.signatureId === undefined && signatures.length > 1) {
    throw new SigningError(
      'Belgede birden çok imza var; hangisinin damgalanacağı signatureId ile belirtilmeli.',
    )
  }

  const value = childNamed(signature, Namespace.SIGNATURE, 'SignatureValue')
  if (value === undefined) throw new SigningError('İmzada ds:SignatureValue yok.')

  const canonicalization = resolveCanonicalization(options, signature)
  const digestAlgorithm = options.digestAlgorithm ?? 'SHA-256'
  const canonical = canonicalizeToBytes(document, {
    algorithm: canonicalization,
    subset: value,
  })
  return { document, signature, imprint: digest(digestAlgorithm, canonical) }
}

/** {@link timestampRequest} ile {@link upgrade} arasında ortak özet hesabı. */
const signatureValueImprint = (
  options: TimestampTarget,
): { imprint: Uint8Array; digestAlgorithm: DigestAlgorithm } => ({
  imprint: locateSignature(options).imprint,
  digestAlgorithm: options.digestAlgorithm ?? 'SHA-256',
})

/** Kanonikleştirme algoritmasını seçenekten ya da imzanın kendisinden çözer. */
const resolveCanonicalization = (
  options: TimestampTarget,
  signature: XmlElement,
): C14nAlgorithm => {
  if (options.canonicalization !== undefined) return options.canonicalization
  const signedInfo = childNamed(signature, Namespace.SIGNATURE, 'SignedInfo')
  const method =
    signedInfo === undefined
      ? undefined
      : childNamed(signedInfo, Namespace.SIGNATURE, 'CanonicalizationMethod')
  const uri = method === undefined ? undefined : getAttributeValue(method, 'Algorithm')
  if (uri === undefined) return 'exc-c14n'
  try {
    return c14nAlgorithmFromUri(uri)
  } catch {
    return 'exc-c14n'
  }
}

/** Alt ağaçta ada göre ilk öğeyi bulur. */
const findIn = (root: XmlElement, namespace: string, localName: string): XmlElement | undefined => {
  for (const element of walkElements(root)) {
    if (element.namespace === namespace && element.localName === localName) return element
  }
  return undefined
}
