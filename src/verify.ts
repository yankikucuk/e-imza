import { verify as nodeVerify, X509Certificate } from 'node:crypto'

import {
  c14nAlgorithmFromUri,
  canonicalizeToBytes,
  type C14nAlgorithm,
} from './c14n/canonicalize.js'
import { fromBase64, timingSafeEqual } from './core/bytes.js'
import { VerificationError } from './core/errors.js'
import { readCertificate, type CertificateInfo } from './pki/certificate.js'
import {
  DIGEST_NODE_NAME,
  DIGEST_URI,
  FILTER2_NAMESPACE,
  Namespace,
  SIGNATURE_DIGEST,
  SIGNATURE_URI,
  Transform,
  type DigestAlgorithm,
  type SignatureAlgorithm,
} from './xades/constants.js'
import { digest } from './xades/signature.js'
import { findElementById } from './xml/edit.js'
import {
  childNamed,
  childrenNamed,
  getAttributeValue,
  textContent,
  walkElements,
  type XmlDocument,
  type XmlElement,
  type XmlNode,
} from './xml/node.js'
import { parseXml } from './xml/parse.js'

/**
 * İmza seviyesi.
 *
 * `XMLDSig` düz bir XML imzasıdır — XAdES nitelikleri yoktur. Kalanlar ETSI
 * seviyeleridir; her biri bir öncekini kapsar.
 */
export type SignatureLevel = 'XMLDSig' | 'BES' | 'EPES' | 'T' | 'LT' | 'LTA'

/** Tek bir referansın doğrulama sonucu. */
export interface ReferenceResult {
  readonly uri: string
  readonly type?: string
  readonly valid: boolean
  readonly digestAlgorithm: DigestAlgorithm
}

/** Doğrulama sırasında fark edilen, ama imzayı geçersiz KILMAYAN durumlar. */
export interface VerificationWarning {
  readonly code:
    | 'certificate-expired-at-signing'
    | 'certificate-not-yet-valid-at-signing'
    | 'certificate-currently-expired'
    | 'signing-certificate-digest-mismatch'
  readonly message: string
}

/** {@link verify} sonucu. */
export type VerificationResult =
  | {
      readonly valid: true
      readonly level: SignatureLevel
      readonly signatureId?: string
      /** İmzalayan sertifikanın okunmuş hâli. */
      readonly signer: CertificateInfo
      /** `xades:SigningTime` varsa. */
      readonly signingTime?: Date
      readonly references: readonly ReferenceResult[]
      readonly signatureAlgorithm: SignatureAlgorithm
      readonly canonicalization: C14nAlgorithm
      /** İmzayı geçersiz kılmayan, ama bilinmesi gereken durumlar. */
      readonly warnings: readonly VerificationWarning[]
    }
  | {
      readonly valid: false
      readonly reason: string
      /** Referanslar çözülebildiyse hangisinin tutmadığını gösterir. */
      readonly references?: readonly ReferenceResult[]
    }

/** {@link verify} seçenekleri. */
export interface VerifyOptions {
  /**
   * Belgede birden çok imza varsa hangisinin doğrulanacağı.
   *
   * Verilmezse ilk `ds:Signature` alınır. Paralel imzalı bir belgede
   * hepsini denetlemek için {@link verifyAll} kullanın.
   */
  readonly signatureId?: string
}

/**
 * XAdES / XMLDSig imzasını doğrular.
 *
 * ## `valid: true` ne demek, ne demek değil
 *
 * Demek olan üç şey:
 * 1. Her `ds:Reference` özeti yeniden hesaplandı ve tuttu,
 * 2. `ds:SignedInfo` kanonikleştirildi ve `ds:SignatureValue` bu baytlar
 *    üzerinde `ds:KeyInfo`'daki sertifikayla kriptografik olarak doğrulandı,
 * 3. `xades:SigningCertificate` varsa, özeti kullanılan sertifikayla tutarlı.
 *
 * Demek OLMAYAN şeyler: sertifikanın güvenilir bir köke bağlandığı, iptal
 * edilmediği, imza anında geçerli olduğu ya da imzanın hukuken bağlayıcı
 * olduğu. Bunların hiçbiri yapısal doğrulamanın konusu değildir; sertifika
 * zinciri ve iptal denetimi çağıranın kendi güven kümesiyle yapılır.
 *
 * Bu ayrımı bulanıklaştırmak, imza kütüphanelerinde en sık görülen sahte
 * güvenlik kaynağıdır: `valid: true` gören çağıran, belgeyi güvenilir sanır.
 * Geçerlilik tarihleriyle ilgili gözlemler `warnings` altında ayrıca
 * raporlanır (`PKI.js#460` bu denetimin hiç yapılmamasından açılmıştı).
 *
 * @param xml - İmzalı belge
 * @param options - {@link VerifyOptions}
 * @returns Doğrulama sonucu; geçersiz imza bir HATA değil, `valid: false` sonucudur
 * @throws {VerificationError} Belgede hiç imza yoksa ya da yapı okunamıyorsa
 */
export const verify = (
  xml: string | XmlDocument,
  options: VerifyOptions = {},
): VerificationResult => {
  const document = typeof xml === 'string' ? parseXml(xml) : xml
  const signatures = findSignatures(document)
  if (signatures.length === 0) throw new VerificationError('Belgede ds:Signature öğesi yok.')

  const target =
    options.signatureId === undefined
      ? signatures[0]
      : signatures.find((s) => getAttributeValue(s, 'Id') === options.signatureId)
  if (target === undefined) {
    throw new VerificationError(`"${options.signatureId ?? ''}" kimlikli imza bulunamadı.`)
  }
  return verifySignature(document, target)
}

/**
 * Belgedeki TÜM imzaları ayrı ayrı doğrular.
 *
 * Paralel imza (aynı belgeyi birden çok kişinin bağımsız imzalaması)
 * `xadesjs#87`de istenip karşılanamamıştı; sebebi, `enveloped-signature`
 * dönüşümünün belgedeki bütün imzaları silmesiydi. Burada dönüşüm yalnızca
 * referansı içeren imzayı çıkarır, dolayısıyla imzalar birbirini kapsar ve
 * her biri bağımsız doğrulanır.
 *
 * @param xml - İmzalı belge
 * @returns Her imza için bir sonuç, belge sırasına göre
 */
export const verifyAll = (xml: string | XmlDocument): readonly VerificationResult[] => {
  const document = typeof xml === 'string' ? parseXml(xml) : xml
  const signatures = findSignatures(document)
  if (signatures.length === 0) throw new VerificationError('Belgede ds:Signature öğesi yok.')
  return signatures.map((signature) => verifySignature(document, signature))
}

/** Belgedeki en dıştaki `ds:Signature` öğelerini bulur. */
const findSignatures = (document: XmlDocument): readonly XmlElement[] => {
  const found: XmlElement[] = []
  const visit = (node: XmlNode): void => {
    if (node.kind !== 'element') return
    if (node.namespace === Namespace.SIGNATURE && node.localName === 'Signature') {
      // İç içe imzalar (karşı imza) burada toplanmaz; onlar kendi
      // bağlamlarında değerlendirilir.
      found.push(node)
      return
    }
    for (const child of node.children) visit(child)
  }
  visit(document.root)
  return found
}

/** Tek bir imzayı doğrular. */
const verifySignature = (document: XmlDocument, signature: XmlElement): VerificationResult => {
  const signedInfo = childNamed(signature, Namespace.SIGNATURE, 'SignedInfo')
  const signatureValueElement = childNamed(signature, Namespace.SIGNATURE, 'SignatureValue')
  if (signedInfo === undefined || signatureValueElement === undefined) {
    return { valid: false, reason: 'ds:SignedInfo ya da ds:SignatureValue eksik.' }
  }

  const canonicalizationUri = algorithmOf(signedInfo, 'CanonicalizationMethod')
  const signatureUri = algorithmOf(signedInfo, 'SignatureMethod')
  if (canonicalizationUri === undefined || signatureUri === undefined) {
    return { valid: false, reason: 'Kanonikleştirme ya da imza algoritması belirtilmemiş.' }
  }

  let canonicalization: C14nAlgorithm
  try {
    canonicalization = c14nAlgorithmFromUri(canonicalizationUri)
  } catch {
    return { valid: false, reason: `Desteklenmeyen kanonikleştirme: ${canonicalizationUri}` }
  }

  const signatureAlgorithm = signatureAlgorithmFromUri(signatureUri)
  if (signatureAlgorithm === undefined) {
    return { valid: false, reason: `Desteklenmeyen imza algoritması: ${signatureUri}` }
  }

  const certificateDer = firstCertificate(signature)
  if (certificateDer === undefined) {
    return { valid: false, reason: 'ds:KeyInfo içinde X.509 sertifikası yok.' }
  }

  // ── 1. Referans doğrulaması ────────────────────────────────────────────
  const references: ReferenceResult[] = []
  for (const reference of childrenNamed(signedInfo, Namespace.SIGNATURE, 'Reference')) {
    const outcome = verifyReference(document, signature, reference)
    if (typeof outcome === 'string') return { valid: false, reason: outcome, references }
    references.push(outcome)
  }
  if (references.length === 0) {
    return { valid: false, reason: 'ds:SignedInfo içinde hiç referans yok.' }
  }
  if (references.some((reference) => !reference.valid)) {
    return {
      valid: false,
      reason: 'Bir ya da daha çok referansın özeti tutmadı — belge imzalandıktan sonra değişmiş.',
      references,
    }
  }

  // ── 2. İmza değeri doğrulaması ─────────────────────────────────────────
  const canonicalSignedInfo = canonicalizeToBytes(document, {
    algorithm: canonicalization,
    subset: signedInfo,
  })
  const signatureValue = fromBase64(textContent(signatureValueElement))

  let signatureOk: boolean
  try {
    const publicKey = new X509Certificate(Buffer.from(certificateDer)).publicKey
    const hash = DIGEST_NODE_NAME[SIGNATURE_DIGEST[signatureAlgorithm]]
    signatureOk = signatureAlgorithm.startsWith('ECDSA')
      ? nodeVerify(
          hash,
          Buffer.from(canonicalSignedInfo),
          { key: publicKey, dsaEncoding: 'ieee-p1363' },
          Buffer.from(signatureValue),
        )
      : nodeVerify(hash, Buffer.from(canonicalSignedInfo), publicKey, Buffer.from(signatureValue))
  } catch (error) {
    return {
      valid: false,
      reason: `İmza değeri değerlendirilemedi: ${error instanceof Error ? error.message : String(error)}`,
      references,
    }
  }
  if (!signatureOk) {
    return {
      valid: false,
      reason: 'İmza değeri sertifikanın açık anahtarıyla doğrulanmadı.',
      references,
    }
  }

  // ── 3. XAdES nitelikleri ───────────────────────────────────────────────
  const signer = readCertificate(certificateDer)
  const properties = findSignedProperties(signature)
  const signingTime = properties === undefined ? undefined : readSigningTime(properties)
  const warnings = collectWarnings(signer, properties, certificateDer, signingTime)

  const signatureId = getAttributeValue(signature, 'Id')
  return {
    valid: true,
    ...(signatureId === undefined ? {} : { signatureId }),
    level: detectLevel(signature, properties),
    signer,
    ...(signingTime === undefined ? {} : { signingTime }),
    references,
    signatureAlgorithm,
    canonicalization,
    warnings,
  }
}

/**
 * Tek bir referansı doğrular.
 *
 * @returns Sonuç, ya da referans hiç çözülemediyse hata metni
 */
const verifyReference = (
  document: XmlDocument,
  signature: XmlElement,
  reference: XmlElement,
): ReferenceResult | string => {
  const uri = getAttributeValue(reference, 'URI')
  if (uri === undefined) return 'Referansta URI özniteliği yok — dış veri desteklenmiyor.'

  const digestMethod = childNamed(reference, Namespace.SIGNATURE, 'DigestMethod')
  const digestValueElement = childNamed(reference, Namespace.SIGNATURE, 'DigestValue')
  if (digestMethod === undefined || digestValueElement === undefined) {
    return 'Referansta özet algoritması ya da değeri eksik.'
  }
  const digestUri = getAttributeValue(digestMethod, 'Algorithm') ?? ''
  const digestAlgorithm = digestAlgorithmFromUri(digestUri)
  if (digestAlgorithm === undefined) return `Desteklenmeyen özet algoritması: ${digestUri}`

  // Dönüşüm zinciri. Bu pakette iki dönüşüm anlamlıdır: imzayı dışarıda
  // bırakan `enveloped-signature` ve kanonikleştirme. XPath süzgeçleri
  // desteklenmiyor ve SESSİZCE ATLANMIYOR — atlamak, imzanın kapsamadığı
  // bir içeriği kapsamış gibi göstermek olurdu.
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
        if (!subtractsAllSignatures(transform)) {
          return (
            'XPath Filter 2.0 dönüşümünde yalnızca bütün imzaları çıkaran ' +
            '(Filter="subtract", //ds:Signature) deyim destekleniyor.'
          )
        }
        omitted = 'all'
        continue
      }
      try {
        canonicalization = c14nAlgorithmFromUri(algorithm)
      } catch {
        return `Desteklenmeyen dönüşüm: ${algorithm}`
      }
    }
  }

  const omit =
    omitted === 'none'
      ? undefined
      : omitted === 'own'
        ? new Set([signature])
        : new Set(allSignatures(document))

  // XMLDSig §4.3.3.2: dönüşümsüz bir aynı-belge referansı, örtük olarak
  // KAPSAYICI Canonical XML 1.0 ile işlenir — `ds:CanonicalizationMethod`
  // ne derse desin. Bu varsayılanı imza yönteminkiyle karıştırmak, iki
  // uygulamanın farklı özet hesaplaması demektir.
  const algorithm = canonicalization ?? 'c14n10'

  let canonical: Uint8Array
  if (uri === '') {
    canonical = canonicalizeToBytes(document, {
      algorithm,
      ...(omit === undefined ? {} : { omit }),
    })
  } else if (uri.startsWith('#')) {
    const id = uri.slice(1)
    if (id.startsWith('xpointer')) return 'XPointer başvuruları desteklenmiyor.'
    const subset = findElementById(document, id)
    if (subset === undefined) {
      return `"${id}" kimlikli öğe bulunamadı ya da birden çok öğe aynı kimliği taşıyor.`
    }
    canonical = canonicalizeToBytes(document, {
      algorithm,
      subset,
      ...(omit === undefined ? {} : { omit }),
    })
  } else {
    return `Dış referanslar desteklenmiyor: ${uri}`
  }

  const expected = fromBase64(textContent(digestValueElement))
  const actual = digest(digestAlgorithm, canonical)
  const type = getAttributeValue(reference, 'Type')
  return {
    uri,
    ...(type === undefined ? {} : { type }),
    valid: timingSafeEqual(actual, expected),
    digestAlgorithm,
  }
}

/**
 * XPath Filter 2.0 dönüşümünün "bütün imzaları çıkar" deyimi olup olmadığını
 * söyler.
 *
 * Bu paket genel bir XPath motoru içermez. İmza kapsamını belirleyen bir
 * ifadeyi yaklaşık değerlendirmek, imzanın kapsamadığı bir içeriği
 * kapsıyormuş gibi göstermek olurdu — dolayısıyla tanınmayan her ifade
 * REDDEDİLİR, sessizce yok sayılmaz.
 *
 * Ön ek serbesttir: ifadedeki ön ek, `XPath` öğesinin kapsamında XMLDSig
 * ad alanına bağlıysa kabul edilir.
 */
const subtractsAllSignatures = (transform: XmlElement): boolean => {
  const xpath = childNamed(transform, FILTER2_NAMESPACE, 'XPath')
  if (xpath === undefined) return false
  if (getAttributeValue(xpath, 'Filter') !== 'subtract') return false

  const expression = textContent(xpath).trim()
  const match = /^\/\/([A-Za-z_][\w.-]*):Signature$/.exec(expression)
  if (match === null) return false
  const prefix = match[1] ?? ''

  // Ön ekin XMLDSig ad alanına bağlı olduğunu, dönüşümün kendi bildirimleri
  // üzerinden doğrula.
  for (const source of [xpath, transform]) {
    for (const declaration of source.namespaceDeclarations) {
      if (declaration.prefix === prefix) return declaration.uri === Namespace.SIGNATURE
    }
  }
  return false
}

/** Belgedeki tüm `ds:Signature` öğeleri — iç içe olanlar dâhil. */
const allSignatures = (document: XmlDocument): readonly XmlElement[] =>
  [...walkElements(document.root)].filter(
    (element) => element.namespace === Namespace.SIGNATURE && element.localName === 'Signature',
  )

/** `Algorithm` özniteliğini okur. */
const algorithmOf = (parent: XmlElement, localName: string): string | undefined => {
  const child = childNamed(parent, Namespace.SIGNATURE, localName)
  return child === undefined ? undefined : getAttributeValue(child, 'Algorithm')
}

/** `ds:KeyInfo` içindeki ilk sertifikayı DER olarak verir. */
const firstCertificate = (signature: XmlElement): Uint8Array | undefined => {
  const keyInfo = childNamed(signature, Namespace.SIGNATURE, 'KeyInfo')
  if (keyInfo === undefined) return undefined
  for (const data of childrenNamed(keyInfo, Namespace.SIGNATURE, 'X509Data')) {
    const certificate = childNamed(data, Namespace.SIGNATURE, 'X509Certificate')
    if (certificate !== undefined) return fromBase64(textContent(certificate))
  }
  return undefined
}

/** İmzaya ait `xades:SignedProperties` öğesini bulur. */
const findSignedProperties = (signature: XmlElement): XmlElement | undefined => {
  for (const element of walkElements(signature)) {
    if (element.namespace === Namespace.XADES && element.localName === 'SignedProperties') {
      return element
    }
  }
  return undefined
}

/** `xades:SigningTime` değerini okur. */
const readSigningTime = (properties: XmlElement): Date | undefined => {
  for (const element of walkElements(properties)) {
    if (element.namespace === Namespace.XADES && element.localName === 'SigningTime') {
      const parsed = new Date(textContent(element))
      return Number.isNaN(parsed.getTime()) ? undefined : parsed
    }
  }
  return undefined
}

/** İmza seviyesini yapıya bakarak belirler. */
const detectLevel = (signature: XmlElement, properties: XmlElement | undefined): SignatureLevel => {
  if (properties === undefined) return 'XMLDSig'
  const names = new Set<string>()
  for (const element of walkElements(signature)) {
    if (element.namespace === Namespace.XADES || element.namespace === Namespace.XADES_141) {
      names.add(element.localName)
    }
  }
  if (names.has('ArchiveTimeStamp')) return 'LTA'
  if (names.has('CertificateValues') || names.has('RevocationValues')) return 'LT'
  if (names.has('SignatureTimeStamp')) return 'T'
  if (names.has('SignaturePolicyIdentifier')) return 'EPES'
  return 'BES'
}

/**
 * İmzayı geçersiz kılmayan, ama raporlanması gereken durumları toplar.
 *
 * Sertifikanın geçerlilik aralığı bilinçli olarak `valid` sonucuna
 * katılmaz — imza anında geçerli olmayan bir sertifikayla atılmış imza
 * yapısal olarak geçerlidir, hukuken değil. Ayrımı kütüphane değil, çağıran
 * verir. Ama sessiz kalmak da doğru olmaz: `PKI.js#460` bu denetimin hiç
 * yapılmamasından açılmıştı.
 */
const collectWarnings = (
  signer: CertificateInfo,
  properties: XmlElement | undefined,
  certificateDer: Uint8Array,
  signingTime: Date | undefined,
): readonly VerificationWarning[] => {
  const warnings: VerificationWarning[] = []

  if (signingTime !== undefined) {
    if (signingTime > signer.notAfter) {
      warnings.push({
        code: 'certificate-expired-at-signing',
        message: `İmza zamanı (${signingTime.toISOString()}) sertifikanın geçerlilik bitişinden (${signer.notAfter.toISOString()}) sonra.`,
      })
    } else if (signingTime < signer.notBefore) {
      warnings.push({
        code: 'certificate-not-yet-valid-at-signing',
        message: `İmza zamanı (${signingTime.toISOString()}) sertifikanın geçerlilik başlangıcından (${signer.notBefore.toISOString()}) önce.`,
      })
    }
  }
  if (new Date() > signer.notAfter) {
    warnings.push({
      code: 'certificate-currently-expired',
      message: `Sertifikanın geçerliliği ${signer.notAfter.toISOString()} tarihinde dolmuş.`,
    })
  }

  // `xades:SigningCertificate` özeti, imzayı atan sertifikanın gerçekten
  // niyet edilen sertifika olduğunu bağlar. Tutmuyorsa imza değeri doğru
  // olsa bile bir tutarsızlık var demektir.
  if (properties !== undefined) {
    const mismatch = signingCertificateMismatch(properties, certificateDer)
    if (mismatch) {
      warnings.push({
        code: 'signing-certificate-digest-mismatch',
        message: 'xades:SigningCertificate özeti, ds:KeyInfo içindeki sertifikayla eşleşmiyor.',
      })
    }
  }
  return warnings
}

/** `xades:SigningCertificate` özetinin tutup tutmadığını söyler. */
const signingCertificateMismatch = (
  properties: XmlElement,
  certificateDer: Uint8Array,
): boolean => {
  for (const element of walkElements(properties)) {
    if (element.namespace !== Namespace.XADES || element.localName !== 'CertDigest') continue
    const method = childNamed(element, Namespace.SIGNATURE, 'DigestMethod')
    const value = childNamed(element, Namespace.SIGNATURE, 'DigestValue')
    if (method === undefined || value === undefined) continue
    const algorithm = digestAlgorithmFromUri(getAttributeValue(method, 'Algorithm') ?? '')
    if (algorithm === undefined) continue
    return !timingSafeEqual(digest(algorithm, certificateDer), fromBase64(textContent(value)))
  }
  return false
}

/** URI'den özet algoritmasını çözer. */
const digestAlgorithmFromUri = (uri: string): DigestAlgorithm | undefined => {
  for (const [key, value] of Object.entries(DIGEST_URI)) {
    if (value === uri) return key as DigestAlgorithm
  }
  return undefined
}

/** URI'den imza algoritmasını çözer. */
const signatureAlgorithmFromUri = (uri: string): SignatureAlgorithm | undefined => {
  for (const [key, value] of Object.entries(SIGNATURE_URI)) {
    if (value === uri) return key as SignatureAlgorithm
  }
  return undefined
}
