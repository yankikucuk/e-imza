import {
  c14nAlgorithmFromUri,
  canonicalizeToBytes,
  type C14nAlgorithm,
} from '../c14n/canonicalize.js'
import { concat, fromBase64 } from '../core/bytes.js'
import { findElementById } from '../xml/edit.js'
import {
  childNamed,
  childrenNamed,
  getAttributeValue,
  walkElements,
  type XmlDocument,
  type XmlElement,
} from '../xml/node.js'

import { Namespace, Transform } from './constants.js'

/**
 * Arşiv zaman damgasının (XAdES-LTA) girdi baytlarını hesaplar.
 *
 * ## Neden ayrı bir modül
 *
 * Bu hesap **iki yerde birden** yapılır: damgayı üretirken ve doğrularken.
 * İkisi bir baytta bile ayrılırsa, kendi ürettiğimiz LTA imzasını kendi
 * doğrulayıcımız reddeder. Tek bir yerde tutmak bu ayrışmayı imkânsız
 * kılıyor.
 *
 * ## Hangi tanım
 *
 * ETSI TS 101 903 v1.4.2 §8.2.1. Girdi, şu sırayla birleştirilir:
 *
 * 1. `ds:SignedInfo` içindeki her `ds:Reference`ın **dönüşümlerden geçmiş
 *    veri nesnesi**, referansların belgedeki sırasıyla,
 * 2. `ds:SignedInfo` (kanonik),
 * 3. `ds:SignatureValue` (kanonik),
 * 4. varsa `ds:KeyInfo` (kanonik),
 * 5. bu arşiv damgasından **önce gelen** imzalanmamış imza özellikleri,
 *    belgedeki sırayla (kanonik),
 * 6. `xades:QualifyingProperties` İÇERMEYEN `ds:Object` öğeleri (kanonik).
 *
 * ## Sınır
 *
 * EN 319 132, arşiv damgası için farklı bir girdi tanımlar; bu paket
 * TS 101 903 v1.4.2 tanımını uygular ve bunu açıkça söyler. Bağımsız bir
 * uygulamayla çapraz doğrulama yapılamadı — zaman damgasının kendisi
 * OpenSSL ile iki yönde sınandı, ama arşiv damgasının GİRDİ HESABI
 * yalnızca kendi testlerimizle sınanmış durumda.
 */

/** {@link archiveTimestampInput} sonucu. */
export interface ArchiveInput {
  /** Damgalanacak baytlar. */
  readonly bytes: Uint8Array
  /** Hesapta kullanılan kanonikleştirme algoritması. */
  readonly canonicalization: C14nAlgorithm
}

/**
 * Bir `ds:Reference`ın dönüşümlerden geçmiş verisini kanonik olarak verir.
 *
 * Doğrulayıcıdaki referans denetimiyle aynı kuralları uygular:
 * `enveloped-signature` imzayı çıkarır, XPath Filter 2.0'ın desteklenen
 * deyimi bütün imzaları çıkarır, ve dönüşüm yazılmamışsa örtük varsayılan
 * KAPSAYICI Canonical XML 1.0'dır (XMLDSig §4.3.3.2).
 *
 * @param document - İmzalı belge
 * @param signature - Referansı içeren `ds:Signature`
 * @param reference - `ds:Reference` öğesi
 * @returns Kanonik veri; referans çözülemezse `undefined`
 */
export const referenceData = (
  document: XmlDocument,
  signature: XmlElement,
  reference: XmlElement,
): Uint8Array | undefined => {
  const uri = getAttributeValue(reference, 'URI')
  if (uri === undefined) return undefined

  let omitted: 'none' | 'own' | 'all' = 'none'
  let canonicalization: C14nAlgorithm | undefined
  const transforms = childNamed(reference, Namespace.SIGNATURE, 'Transforms')
  if (transforms !== undefined) {
    for (const transform of childrenNamed(transforms, Namespace.SIGNATURE, 'Transform')) {
      const algorithm = getAttributeValue(transform, 'Algorithm') ?? ''
      if (algorithm === Transform.ENVELOPED_SIGNATURE) {
        omitted = 'own'
        continue
      }
      if (algorithm === Transform.XPATH_FILTER2) {
        omitted = 'all'
        continue
      }
      try {
        canonicalization = c14nAlgorithmFromUri(algorithm)
      } catch {
        return undefined
      }
    }
  }

  const omit =
    omitted === 'none'
      ? undefined
      : omitted === 'own'
        ? new Set([signature])
        : new Set(
            [...walkElements(document.root)].filter(
              (element) =>
                element.namespace === Namespace.SIGNATURE && element.localName === 'Signature',
            ),
          )

  const algorithm = canonicalization ?? 'c14n10'
  if (uri === '') {
    return canonicalizeToBytes(document, {
      algorithm,
      ...(omit === undefined ? {} : { omit }),
    })
  }
  if (!uri.startsWith('#')) return undefined
  const subset = findElementById(document, uri.slice(1))
  if (subset === undefined) return undefined
  return canonicalizeToBytes(document, {
    algorithm,
    subset,
    ...(omit === undefined ? {} : { omit }),
  })
}

/**
 * Arşiv zaman damgasının girdi baytlarını hesaplar.
 *
 * @param document - İmzalı belge
 * @param signature - Damgalanacak `ds:Signature`
 * @param canonicalization - Kullanılacak kanonikleştirme
 * @param before - Doğrularken: hesaba katılacak son öğe olan arşiv damgası.
 *   Bu öğe ve ondan SONRAKİ imzalanmamış özellikler girdiye girmez.
 *   Üretirken verilmez; o an var olan bütün özellikler girdiye girer.
 * @returns Damgalanacak baytlar
 */
export const archiveTimestampInput = (
  document: XmlDocument,
  signature: XmlElement,
  canonicalization: C14nAlgorithm,
  before?: XmlElement,
): ArchiveInput => {
  const parts: Uint8Array[] = []

  // 1. Referansların verisi, belgedeki sırayla.
  const signedInfo = childNamed(signature, Namespace.SIGNATURE, 'SignedInfo')
  if (signedInfo !== undefined) {
    for (const reference of childrenNamed(signedInfo, Namespace.SIGNATURE, 'Reference')) {
      const data = referenceData(document, signature, reference)
      if (data !== undefined) parts.push(data)
    }
    // 2. SignedInfo.
    parts.push(canonicalizeToBytes(document, { algorithm: canonicalization, subset: signedInfo }))
  }

  // 3. SignatureValue.
  const value = childNamed(signature, Namespace.SIGNATURE, 'SignatureValue')
  if (value !== undefined) {
    parts.push(canonicalizeToBytes(document, { algorithm: canonicalization, subset: value }))
  }

  // 4. KeyInfo, varsa.
  const keyInfo = childNamed(signature, Namespace.SIGNATURE, 'KeyInfo')
  if (keyInfo !== undefined) {
    parts.push(canonicalizeToBytes(document, { algorithm: canonicalization, subset: keyInfo }))
  }

  // 5. Bu damgadan ÖNCE gelen imzalanmamış imza özellikleri.
  const unsigned = findUnsignedSignatureProperties(signature)
  if (unsigned !== undefined) {
    for (const property of unsigned.children) {
      if (property.kind !== 'element') continue
      if (property === before) break
      parts.push(canonicalizeToBytes(document, { algorithm: canonicalization, subset: property }))
    }
  }

  // 6. QualifyingProperties İÇERMEYEN ds:Object öğeleri.
  for (const object of childrenNamed(signature, Namespace.SIGNATURE, 'Object')) {
    const holdsQualifying = [...walkElements(object)].some(
      (element) =>
        element.namespace === Namespace.XADES && element.localName === 'QualifyingProperties',
    )
    if (holdsQualifying) continue
    parts.push(canonicalizeToBytes(document, { algorithm: canonicalization, subset: object }))
  }

  return { bytes: concat(...parts), canonicalization }
}

/** İmzanın `xades:UnsignedSignatureProperties` öğesini bulur. */
export const findUnsignedSignatureProperties = (signature: XmlElement): XmlElement | undefined => {
  for (const element of walkElements(signature)) {
    if (
      element.namespace === Namespace.XADES &&
      element.localName === 'UnsignedSignatureProperties'
    ) {
      return element
    }
  }
  return undefined
}

/**
 * Bir zaman damgası öğesinin gömülü jetonunu verir.
 *
 * `xades:SignatureTimeStamp` ve `xades141:ArchiveTimeStamp` aynı iç yapıyı
 * kullanır: kanonikleştirme yöntemi artı `xades:EncapsulatedTimeStamp`.
 *
 * @param element - Zaman damgası öğesi
 * @returns Jeton baytları; yoksa `undefined`
 */
export const encapsulatedToken = (element: XmlElement): Uint8Array | undefined => {
  const encapsulated = childNamed(element, Namespace.XADES, 'EncapsulatedTimeStamp')
  if (encapsulated === undefined) return undefined
  let text = ''
  for (const child of encapsulated.children) {
    if (child.kind === 'text') text += child.value
  }
  return fromBase64(text)
}
