import { randomUUID, sign as nodeSign, type KeyObject } from 'node:crypto'

import { derOctetString, derSequence, derNull, derOid } from './asn1/der.js'
import { C14N_URI, canonicalizeToBytes, type C14nAlgorithm } from './c14n/canonicalize.js'
import { toBase64, wrapBase64 } from './core/bytes.js'
import { SigningError } from './core/errors.js'
import { readCertificate } from './pki/certificate.js'
import {
  DIGEST_NODE_NAME,
  ReferenceType,
  SIGNATURE_DIGEST,
  Namespace as XmlDsigNamespace,
  Ubl,
  type CommitmentType,
  type DigestAlgorithm,
  type SignatureAlgorithm,
} from './xades/constants.js'
import { element } from './xades/element.js'
import {
  buildSignature,
  buildSignedInfo,
  buildSignedProperties,
  deriveIds,
  digest,
  envelopedTransforms,
  parallelTransforms,
  type ProductionPlace,
  type ReferenceInput,
  type SignaturePolicy,
  type SignerRole,
} from './xades/signature.js'
import { appendChildren, replaceElement } from './xml/edit.js'
import { childNamed, walkElements, type XmlDocument, type XmlElement } from './xml/node.js'
import { parseXml } from './xml/parse.js'
import { serializeXml } from './xml/serialize.js'

/**
 * İmzanın belgeye nereye yerleştirileceği.
 *
 * - `ubl-extension` — `ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent`
 *   içine. UBL-TR e-Fatura ve e-İrsaliye'nin beklediği yer.
 * - `enveloped` — kök öğenin sonuna.
 *
 * İkisinde de belge referansı `URI=""` ile tüm belgeyi kapsar ve
 * `enveloped-signature` dönüşümü imzanın kendisini dışarıda bırakır.
 */
export type SignaturePlacement = 'ubl-extension' | 'enveloped'

/** İmzalayan tarafın kimlik malzemesi. */
export interface SignerInput {
  /** İmzalayan sertifika (DER). */
  readonly certificate: Uint8Array
  /** Ara ve kök sertifikalar (DER); `ds:KeyInfo` içine yazılır. */
  readonly chain?: readonly Uint8Array[]
}

/** {@link sign} ve {@link prepare} için ortak seçenekler. */
export interface SignatureOptions {
  /** İmzalanacak belge — metin ya da ayrıştırılmış hâli. */
  readonly xml: string | XmlDocument
  /** İmzalayan sertifika ve zinciri. */
  readonly signer: SignerInput
  /** Yerleşim; varsayılan `ubl-extension`. */
  readonly placement?: SignaturePlacement
  /**
   * İmza algoritması. Verilmezse sertifikanın anahtar türünden ve
   * {@link digestAlgorithm} değerinden türetilir.
   */
  readonly signatureAlgorithm?: SignatureAlgorithm
  /** Özet algoritması; varsayılan `SHA-256`. */
  readonly digestAlgorithm?: DigestAlgorithm
  /**
   * Kanonikleştirme; varsayılan `exc-c14n`.
   *
   * UBL-TR belgelerinde dışlayıcı biçim tercih edilir: fatura pek çok ad
   * alanı bildirir ve kapsayıcı biçim, imzalanan alt kümeye kullanılmayan
   * bildirimleri de taşır.
   */
  readonly canonicalization?: C14nAlgorithm
  /** İmza zamanı; `null` verilirse `xades:SigningTime` hiç yazılmaz. */
  readonly signingTime?: Date | null
  /** İmza politikası — verilirse imza EPES seviyesinde olur. */
  readonly policy?: SignaturePolicy | 'implied'
  readonly productionPlace?: ProductionPlace
  readonly signerRole?: SignerRole
  readonly commitmentType?: CommitmentType
  /** İmzanın kök kimliği; verilmezse üretilir. */
  readonly id?: string
  /**
   * İmza, belgedeki DİĞER imzalardan bağımsız olsun mu. Varsayılan `false`.
   *
   * Varsayılan davranış (`enveloped-signature` dönüşümü) yalnızca imzanın
   * KENDİSİNİ kapsam dışında bırakır; standart budur ve tek imzalı belgede
   * doğru olan da budur. Ama sonucu şudur: belgeye ikinci bir imza
   * eklendiğinde birinci imzanın kapsadığı içerik değişir ve birinci imza
   * geçersiz olur.
   *
   * `true` verilince XPath Filter 2.0 ile bütün `ds:Signature` öğeleri
   * kapsam dışında bırakılır; imzacılar aynı içeriği imzalar ve imzalar
   * birbirinden bağımsız olur. Paralel imzanın (`xadesjs#87`) gerçek
   * çözümü budur.
   *
   * UBL-TR e-Fatura tek imza bekler; orada varsayılan doğrudur.
   */
  readonly parallel?: boolean
}

/** {@link sign} seçenekleri — özel anahtar burada. */
export interface SignOptions extends SignatureOptions {
  /** İmzalamada kullanılacak özel anahtar. */
  readonly privateKey: KeyObject
}

/**
 * Dışarıda imzalanmayı bekleyen imza.
 *
 * Bu tip, özel anahtara doğrudan erişilemeyen her durumun cevabıdır: akıllı
 * kart (NES), donanım güvenlik modülündeki mali mühür, bulut anahtar
 * kasası, uzak imza servisi. `xadesjs#85` ve `#133`, `node-signpdf#270` ve
 * `#272` hep bu boşluktan açıldı — kütüphaneler yalnızca "anahtarı bana
 * ver" diyebiliyor, "şu baytları imzala ve sonucu getir" diyemiyordu.
 */
export interface PendingSignature {
  /**
   * İmzalanacak baytlar — `ds:SignedInfo`'nun kanonik hâli.
   *
   * PKCS#11'de `CKM_SHA256_RSA_PKCS` gibi özetleyen bir mekanizma
   * kullanıyorsanız doğrudan bunu verin.
   */
  readonly dataToSign: Uint8Array
  /**
   * {@link dataToSign} baytlarının özeti.
   *
   * `CKM_ECDSA` gibi ham imzalayan mekanizmalar bunu ister.
   */
  readonly digest: Uint8Array
  /**
   * RSA PKCS#1 v1.5 için DER `DigestInfo` yapısı.
   *
   * `CKM_RSA_PKCS` özet değil, DigestInfo bekler; kartların çoğu bu
   * mekanizmayı kullanır. Yapıyı elle kurmak, çağıranın bu paketle aynı
   * ASN.1 işini tekrar yazması demek olurdu. EC anahtarlarda `undefined`.
   */
  readonly digestInfo?: Uint8Array
  /** Kullanılacak imza algoritması. */
  readonly signatureAlgorithm: SignatureAlgorithm
  /** Özet algoritması. */
  readonly digestAlgorithm: DigestAlgorithm
  /**
   * İç durum — {@link complete} bunu kullanır.
   *
   * @internal
   */
  readonly document: XmlDocument
  /** @internal */
  readonly signatureValueElement: XmlElement
}

const DEFAULT_DIGEST: DigestAlgorithm = 'SHA-256'
const DEFAULT_C14N: C14nAlgorithm = 'exc-c14n'

/** RSA PKCS#1 v1.5 `DigestInfo` için özet algoritması OID'leri. */
const DIGEST_OID: Readonly<Record<DigestAlgorithm, string>> = {
  'SHA-256': '2.16.840.1.101.3.4.2.1',
  'SHA-384': '2.16.840.1.101.3.4.2.2',
  'SHA-512': '2.16.840.1.101.3.4.2.3',
}

/**
 * Belgeyi XAdES ile imzalar.
 *
 * @param options - {@link SignOptions}
 * @returns İmzalanmış belge (XML metni)
 * @throws {SigningError} Yerleşim noktası bulunamazsa ya da girdi tutarsızsa
 *
 * @example UBL-TR e-Fatura
 * ```ts
 * const { privateKey, certificate, chain } = loadPkcs12(p12, sifre)
 * const imzali = sign({
 *   xml: faturaXml,
 *   signer: { certificate, chain },
 *   privateKey,
 *   commitmentType: 'proof-of-origin',
 *   productionPlace: { city: 'İstanbul', country: 'TR' },
 * })
 * ```
 */
export const sign = (options: SignOptions): string => {
  const pending = prepare(options)
  const signature = signWithKey(pending, options.privateKey)
  return complete(pending, signature)
}

/**
 * İmzayı, imza değeri dışında tamamen hazırlar.
 *
 * Dönen {@link PendingSignature.dataToSign} baytları dışarıda imzalanır —
 * akıllı kartta, donanım modülünde ya da uzak bir serviste — ve sonuç
 * {@link complete} ile yerine konur. Özel anahtar bu sürece hiç girmez.
 *
 * @param options - {@link SignatureOptions}
 * @returns İmzalanmayı bekleyen imza
 *
 * @example Akıllı kartla imzalama
 * ```ts
 * const bekleyen = prepare({ xml, signer: { certificate } })
 * const imza = await kart.imzala(bekleyen.digestInfo ?? bekleyen.dataToSign)
 * const imzali = complete(bekleyen, imza)
 * ```
 */
export const prepare = (options: SignatureOptions): PendingSignature => {
  const digestAlgorithm = options.digestAlgorithm ?? DEFAULT_DIGEST
  const canonicalization = options.canonicalization ?? DEFAULT_C14N
  const signatureAlgorithm =
    options.signatureAlgorithm ??
    defaultSignatureAlgorithm(options.signer.certificate, digestAlgorithm)

  if (SIGNATURE_DIGEST[signatureAlgorithm] !== digestAlgorithm) {
    throw new SigningError(
      `${signatureAlgorithm} algoritması ${SIGNATURE_DIGEST[signatureAlgorithm]} kullanır, ` +
        `ama özet algoritması ${digestAlgorithm} olarak verildi.`,
    )
  }

  const ids = deriveIds(options.id ?? `Signature-${randomUUID()}`)
  const source = typeof options.xml === 'string' ? parseXml(options.xml) : options.xml

  const signedProperties = buildSignedProperties({
    ids,
    certificate: options.signer.certificate,
    digestAlgorithm,
    signingTime: options.signingTime === undefined ? new Date() : options.signingTime,
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    ...(options.productionPlace === undefined ? {} : { productionPlace: options.productionPlace }),
    ...(options.signerRole === undefined ? {} : { signerRole: options.signerRole }),
    ...(options.commitmentType === undefined ? {} : { commitmentType: options.commitmentType }),
  })

  // Özetleri hesaplayabilmek için imzanın belgedeki YERİNİ bilmek gerekir.
  // Bu yüzden önce bir iskelet yerleştirilir. İçindeki özet ve imza değeri
  // yer tutucudur ve sonuca etki etmez: belge referansı imzanın tamamını
  // dışarıda bırakır, `SignedProperties` referansı ise yalnızca kendi alt
  // ağacını kapsar ve o ağaç şimdiden nihai hâlindedir.
  const placeholder = buildSignature({
    ids,
    signedInfo: buildSignedInfo({
      ids,
      canonicalization,
      signatureAlgorithm,
      references: [],
    }),
    signatureValue: '',
    certificate: options.signer.certificate,
    chain: options.signer.chain ?? [],
    signedProperties,
  })

  const withSkeleton = insertSignature(source, placeholder, options.placement ?? 'ubl-extension')
  const inserted = locate(
    withSkeleton,
    (candidate) => candidate.localName === 'Signature' && hasId(candidate, ids.signature),
  )
  const insertedProperties = locate(
    withSkeleton,
    (candidate) =>
      candidate.localName === 'SignedProperties' && hasId(candidate, ids.signedProperties),
  )

  // Paralel kipte bütün imzalar kapsam dışında; varsayılanda yalnızca
  // bu imza. Dönüşüm listesi ile `omit` kümesi AYNI şeyi söylemek
  // zorunda: biri diğerinden ayrılırsa imza kendi doğrulayıcısıyla bile
  // tutmaz.
  const parallel = options.parallel ?? false
  const excluded = parallel
    ? new Set<XmlElement>(
        [...walkElements(withSkeleton.root)].filter(
          (candidate) =>
            candidate.namespace === XmlDsigNamespace.SIGNATURE &&
            candidate.localName === 'Signature',
        ),
      )
    : new Set<XmlElement>([inserted])

  const references: ReferenceInput[] = [
    {
      id: ids.documentReference,
      uri: '',
      transforms: parallel
        ? parallelTransforms(canonicalization)
        : envelopedTransforms(canonicalization),
      digestAlgorithm,
      digestValue: digest(
        digestAlgorithm,
        canonicalizeToBytes(withSkeleton, {
          algorithm: canonicalization,
          omit: excluded,
        }),
      ),
    },
    {
      uri: `#${ids.signedProperties}`,
      type: ReferenceType.SIGNED_PROPERTIES,
      // Kanonikleştirme dönüşümü AÇIKÇA yazılır. XMLDSig §4.3.3.2'ye göre
      // dönüşümsüz bir aynı-belge referansı örtük olarak KAPSAYICI c14n 1.0
      // ile işlenir — `ds:CanonicalizationMethod` ne derse desin. Bu ayrım
      // sıkça gözden kaçar ve iki uygulama farklı özet hesaplar. Açık
      // yazınca belirsizlik kalmıyor.
      transforms: [{ algorithm: C14N_URI[canonicalization] }],
      digestAlgorithm,
      digestValue: digest(
        digestAlgorithm,
        canonicalizeToBytes(withSkeleton, {
          algorithm: canonicalization,
          subset: insertedProperties,
        }),
      ),
    },
  ]

  const signedInfo = buildSignedInfo({ ids, canonicalization, signatureAlgorithm, references })
  const placeholderSignedInfo = locate(
    withSkeleton,
    (candidate) => candidate.localName === 'SignedInfo' && hasId(candidate, ids.signedInfo),
  )
  const withSignedInfo = replaceElement(withSkeleton, placeholderSignedInfo, signedInfo)

  const finalSignedInfo = locate(
    withSignedInfo,
    (candidate) => candidate.localName === 'SignedInfo' && hasId(candidate, ids.signedInfo),
  )
  const dataToSign = canonicalizeToBytes(withSignedInfo, {
    algorithm: canonicalization,
    subset: finalSignedInfo,
  })
  const dataDigest = digest(digestAlgorithm, dataToSign)

  const signatureValueElement = locate(
    withSignedInfo,
    (candidate) => candidate.localName === 'SignatureValue' && hasId(candidate, ids.signatureValue),
  )

  return {
    dataToSign,
    digest: dataDigest,
    ...(signatureAlgorithm.startsWith('RSA-SHA')
      ? { digestInfo: buildDigestInfo(digestAlgorithm, dataDigest) }
      : {}),
    signatureAlgorithm,
    digestAlgorithm,
    document: withSignedInfo,
    signatureValueElement,
  }
}

/**
 * Dışarıda üretilmiş imza değerini yerine koyar ve belgeyi tamamlar.
 *
 * @param pending - {@link prepare} çıktısı
 * @param signatureValue - Ham imza baytları
 * @returns İmzalanmış belge (XML metni)
 *
 * @remarks
 * ECDSA imzası **ham `r‖s`** biçiminde beklenir, ASN.1 DER değil. XMLDSig
 * bunu şart koşar; kartların ve modüllerin çoğu zaten ham biçim üretir, ama
 * OpenSSL DER üretir ve dönüştürmek çağıranın işidir.
 */
export const complete = (pending: PendingSignature, signatureValue: Uint8Array): string => {
  if (signatureValue.length === 0) throw new SigningError('İmza değeri boş.')
  const filled: XmlElement = {
    ...pending.signatureValueElement,
    children: [{ kind: 'text', value: wrapBase64(toBase64(signatureValue)) }],
  }
  return serializeXml(replaceElement(pending.document, pending.signatureValueElement, filled))
}

/**
 * Bekleyen imzayı yerel bir özel anahtarla imzalar.
 *
 * @param pending - {@link prepare} çıktısı
 * @param privateKey - Özel anahtar
 * @returns Ham imza baytları
 */
export const signWithKey = (pending: PendingSignature, privateKey: KeyObject): Uint8Array => {
  const hash = DIGEST_NODE_NAME[pending.digestAlgorithm]
  if (pending.signatureAlgorithm.startsWith('ECDSA')) {
    // XMLDSig ham `r‖s` ister; Node varsayılan olarak DER üretir.
    // `ieee-p1363` tam olarak istenen biçimi verir.
    return new Uint8Array(
      nodeSign(hash, Buffer.from(pending.dataToSign), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      }),
    )
  }
  return new Uint8Array(nodeSign(hash, Buffer.from(pending.dataToSign), privateKey))
}

/** RSA PKCS#1 v1.5'in beklediği `DigestInfo` yapısını kurar. */
const buildDigestInfo = (algorithm: DigestAlgorithm, value: Uint8Array): Uint8Array =>
  derSequence(derSequence(derOid(DIGEST_OID[algorithm]), derNull()), derOctetString(value))

/** Sertifikanın anahtar türünden varsayılan imza algoritmasını seçer. */
const defaultSignatureAlgorithm = (
  certificate: Uint8Array,
  digestAlgorithm: DigestAlgorithm,
): SignatureAlgorithm => {
  const suffix = digestAlgorithm.replace('-', '')
  const info = readCertificate(certificate)
  if (info.keyAlgorithm === 'ec') return `ECDSA-${suffix}` as SignatureAlgorithm
  if (info.keyAlgorithm === 'rsa') return `RSA-${suffix}` as SignatureAlgorithm
  throw new SigningError(
    'Sertifikanın anahtar algoritması tanınmadı; signatureAlgorithm açıkça verilmeli.',
  )
}

/** İmzayı belgeye yerleştirir. */
const insertSignature = (
  document: XmlDocument,
  signature: XmlElement,
  placement: SignaturePlacement,
): XmlDocument => {
  if (placement === 'enveloped') return appendChildren(document, document.root, signature)

  const extensions = childNamed(document.root, Ubl.EXTENSION, 'UBLExtensions')
  if (extensions === undefined) {
    throw new SigningError(
      'Belgede ext:UBLExtensions yok. UBL-TR imzası buraya yerleşir; ' +
        "belgeyi boş bir ext:ExtensionContent ile üretin ya da placement: 'enveloped' kullanın.",
    )
  }

  // Uygun uzantı: içeriği ya boş olan ya da yalnızca imza taşıyan ilk
  // `ext:ExtensionContent`. Başka içerik taşıyanlara dokunulmaz — orada
  // e-Arşiv gönderim bilgisi gibi başka veriler olabilir ve üzerine yazmak
  // veri kaybıdır.
  //
  // İmzaların AYNI kapta toplanması paralel imza için şarttır: her imzaya
  // yeni bir `ext:UBLExtension` açmak, imzalar kapsam dışında bırakılsa
  // bile geride boş bir sarmalayıcı bırakır ve belgenin kanonik biçimini
  // değiştirir — önceki imzalar geçersiz olur.
  for (const extension of extensions.children) {
    if (extension.kind !== 'element') continue
    const content = childNamed(extension, Ubl.EXTENSION, 'ExtensionContent')
    if (content === undefined) continue
    const onlySignatures = content.children.every(
      (child) =>
        child.kind === 'element' &&
        child.namespace === XmlDsigNamespace.SIGNATURE &&
        child.localName === 'Signature',
    )
    if (onlySignatures) {
      return replaceElement(document, content, {
        ...content,
        children: [...content.children, signature],
      })
    }
  }

  // Uygun uzantı yoksa yenisi eklenir — var olanlara dokunulmaz.
  const ext = (localName: string, children: readonly XmlElement[]): XmlElement =>
    element(Ubl.EXTENSION, 'ext', localName, children)
  return replaceElement(document, extensions, {
    ...extensions,
    children: [...extensions.children, ext('UBLExtension', [ext('ExtensionContent', [signature])])],
  })
}

/** Belgede tek bir öğeyi bulur; bulunamazsa hata verir. */
const locate = (document: XmlDocument, match: (element: XmlElement) => boolean): XmlElement => {
  for (const candidate of walkElements(document.root)) {
    if (match(candidate)) return candidate
  }
  throw new SigningError('İmza iskeletindeki bir öğe belgede bulunamadı.')
}

/** Öğenin `Id` özniteliğini karşılaştırır. */
const hasId = (candidate: XmlElement, id: string): boolean =>
  candidate.attributes.some((a) => a.localName === 'Id' && a.value === id)
