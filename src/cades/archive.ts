import { createHash } from 'node:crypto'

import {
  asOctetString,
  asOid,
  asSequence,
  decodeDer,
  derOctetString,
  derSequence,
  type DerNode,
} from '../asn1/der.js'
import { concat, toHex } from '../core/bytes.js'
import { SigningError } from '../core/errors.js'
import { digestAlgorithmIdentifier, type CmsDigest } from '../pki/cms-build.js'

/**
 * CAdES arşiv zaman damgası — `archive-time-stamp-v3`.
 *
 * Kaynak: **ETSI TS 101 733 V2.2.1 (2013-04) §6.4.2 ve §6.4.3.** Bu modülün
 * her satırı o iki maddeden geliyor ve maddelerin kendi cümleleri yorum
 * olarak taşınıyor — çünkü buradaki tek risk, girdiyi standardın dediğinden
 * farklı hesaplamak. Öyle bir hata, ürettiğimiz damganın yalnızca kendi
 * doğrulayıcımızda tutması demektir.
 *
 * ## Neden ATSv3 imzayı bozmadan eklenebiliyor
 *
 * Damganın girdisi `SignerInfo`nun **`unsignedAttrs` DIŞINDAKİ** alanlarını
 * kapsıyor (§6.4.3 madde 3). Damganın kendisi `unsignedAttrs`a eklendiği
 * için girdiyi değiştirmiyor; ikinci bir arşiv damgası da aynı sebeple
 * mümkün. `unsignedAttrs` yine de korumasız kalmıyor: içerikleri
 * {@link buildAtsHashIndex} ile özetlenip girdinin dördüncü bileşenine
 * giriyor.
 */

/** `ats-hash-index` özniteliğinin OID'i — TS 101 733 §6.4.2. */
export const ATS_HASH_INDEX_OID = '0.4.0.1733.2.5'

/**
 * Arşiv damgası girdisini oluşturan **ham** bileşenler.
 *
 * Hepsi kaynaktaki baytlar; hiçbiri yeniden kodlanmıyor. §6.4.3: bileşenler
 * "ikili kodlanmış hâlleriyle, hiçbir değişiklik olmadan, etiket, uzunluk
 * ve değer baytları dâhil" birleştirilir.
 */
export interface ArchiveComponents {
  /** §6.4.3 madde 1 — `SignedData.encapContentInfo.eContentType`. */
  readonly eContentTypeDer: Uint8Array
  /** Sarmalanan içerik; ayrık imzada `undefined`. */
  readonly content?: Uint8Array
  /**
   * §6.4.3 madde 3 — `version`, `sid`, `digestAlgorithm`, `signedAttrs`,
   * `signatureAlgorithm`, `signature`; **görünme sıralarıyla**.
   *
   * `signedAttrs` burada kaynaktaki `[0] IMPLICIT` etiketiyle durur.
   * İmzalama hesabında dış etiket `SET`e çevrilir (RFC 5652 §5.4) ama
   * burada "hiçbir değişiklik olmadan" deniyor — iki hesap bilerek farklı.
   */
  readonly signerFields: readonly Uint8Array[]
  /** §6.4.2 — `SignedData.certificates` içindeki her `CertificateChoices`. */
  readonly certificateInstances: readonly Uint8Array[]
  /** §6.4.2 — `SignedData.crls` içindeki her `RevocationInfoChoice`. */
  readonly crlInstances: readonly Uint8Array[]
  /** §6.4.2 — `SignerInfo.unsignedAttrs` içindeki her `Attribute`. */
  readonly unsignedAttributeInstances: readonly Uint8Array[]
}

/**
 * Arşiv damgası için gereken ham bileşenleri çıkarır.
 *
 * Yapı, `parseCmsSignedData` yerine burada **yeniden** dolaşılıyor. Sebep
 * şu: o ayrıştırıcı anlamlı değerleri (OID metni, `bigint` seri numarası,
 * `SET`e çevrilmiş `signedAttrs`) üretmek için tasarlandı; arşiv damgasının
 * ihtiyacı ise tam tersi — kaynaktaki bayt dilimlerinin ta kendisi. Aynı
 * fonksiyondan iki farklı sözleşme beklemek, ikisinden birini sessizce
 * bozmanın yolu.
 *
 * @param cms - `ContentInfo` DER kodlaması
 * @returns Ham bileşenler
 * @throws {SigningError} Yapı `SignedData` değilse ya da imzacı yoksa
 */
export const readArchiveComponents = (cms: Uint8Array): ArchiveComponents => {
  const contentInfo = asSequence(decodeDer(cms))
  const signedDataNode = contentInfo[1]?.children[0]
  if (signedDataNode === undefined) throw new SigningError('CMS: SignedData bulunamadı.')
  const fields = asSequence(signedDataNode)

  // SEQUENCE { version, digestAlgorithms, encapContentInfo,
  //            [0] certificates?, [1] crls?, signerInfos }
  const encapNode = fields[2]
  if (encapNode === undefined) throw new SigningError('CMS: encapContentInfo yok.')
  const encap = asSequence(encapNode)
  const eContentType = encap[0]
  if (eContentType === undefined) throw new SigningError('CMS: eContentType yok.')
  const eContent = encap[1]?.children[0]

  const context = (tagNumber: number): DerNode | undefined =>
    fields.find((node) => node.tagClass === 'context' && node.tagNumber === tagNumber)

  // §6.4.2: "her CertificateChoices örneği" — tür süzgeci YOK. Yalnızca
  // düz X.509'ları almak, kaptaki başka bir seçimi indeksten düşürür ve
  // doğrulayan taraf o bileşeni korumasız sayar.
  const certificateInstances = (context(0)?.children ?? []).map((node) => node.raw)
  const crlInstances = (context(1)?.children ?? []).map((node) => node.raw)

  const signerInfosNode = [...fields]
    .reverse()
    .find((node) => node.tagClass === 'universal' && node.tagNumber === 17)
  const signer = signerInfosNode?.children[0]
  if (signer === undefined) throw new SigningError('CMS yapısında imzacı yok.')

  const signerFields = asSequence(signer)
  // `unsignedAttrs` ([1] IMPLICIT) girdiye GİRMEZ; ondan öncesi girer.
  const unsignedIndex = signerFields.findIndex(
    (field) => field.tagClass === 'context' && field.tagNumber === 1,
  )
  const included = unsignedIndex === -1 ? signerFields : signerFields.slice(0, unsignedIndex)
  const unsignedAttributeInstances =
    unsignedIndex === -1 ? [] : (signerFields[unsignedIndex]?.children ?? []).map((n) => n.raw)

  return {
    eContentTypeDer: eContentType.raw,
    ...(eContent === undefined ? {} : { content: asOctetString(eContent) }),
    signerFields: included.map((field) => field.raw),
    certificateInstances,
    crlInstances,
    unsignedAttributeInstances,
  }
}

/** Çözümlenmiş `ATSHashIndex`. */
export interface AtsHashIndex {
  /** Özet algoritması OID'i. */
  readonly hashAlgorithmOid: string
  readonly certificatesHashIndex: readonly Uint8Array[]
  readonly crlsHashIndex: readonly Uint8Array[]
  readonly unsignedAttrsHashIndex: readonly Uint8Array[]
}

/** SHA-256'nın OID'i — `hashIndAlgorithm` alanının DEFAULT değeri. */
const SHA256_OID = '2.16.840.1.101.3.4.2.1'

/** `CmsDigest` → OID. */
const DIGEST_OID: Readonly<Record<CmsDigest, string>> = {
  sha256: SHA256_OID,
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

/**
 * `ATSHashIndex` üretir — TS 101 733 §6.4.2.
 *
 * ```text
 * ATSHashIndex ::= SEQUENCE {
 *     hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
 *     certificatesHashIndex    SEQUENCE OF OCTET STRING,
 *     crlsHashIndex            SEQUENCE OF OCTET STRING,
 *     unsignedAttrsHashIndex   SEQUENCE OF OCTET STRING
 * }
 * ```
 *
 * Üç indeksin de o an mevcut **her** örneği içermesi ve başka hiçbir değer
 * içermemesi şart (§6.4.2: "shall be included … No other hash value shall
 * be included"). Her özet, bileşenin etiket-uzunluk-değer baytlarının
 * tamamı üzerinde hesaplanır.
 *
 * @param components - {@link readArchiveComponents} çıktısı
 * @param hash - Özet algoritması; arşiv damgasınınkiyle **aynı** olmalı
 * @returns `ATSHashIndex` DER kodlaması
 */
export const buildAtsHashIndex = (
  components: ArchiveComponents,
  hash: CmsDigest = 'sha256',
): Uint8Array => {
  const digestOf = (bytes: Uint8Array): Uint8Array =>
    derOctetString(new Uint8Array(createHash(hash).update(bytes).digest()))
  const index = (items: readonly Uint8Array[]): Uint8Array => derSequence(...items.map(digestOf))

  // DEFAULT alanı, değeri varsayılana eşitse DER'de YAZILMAZ. Yazmak,
  // kodlamayı DER'den çıkarır ve baytları karşılaştıran her doğrulayıcıda
  // farklı bir `ATSHashIndex` üretir.
  const algorithm = hash === 'sha256' ? [] : [digestAlgorithmIdentifier(hash)]

  return derSequence(
    ...algorithm,
    index(components.certificateInstances),
    index(components.crlInstances),
    index(components.unsignedAttributeInstances),
  )
}

/**
 * `ATSHashIndex` çözümler.
 *
 * @param der - `ATSHashIndex` DER kodlaması
 * @returns Çözümlenmiş indeks
 * @throws {SigningError} Yapı beklenen biçimde değilse
 */
export const parseAtsHashIndex = (der: Uint8Array): AtsHashIndex => {
  const fields = asSequence(decodeDer(der))
  // İlk alan DEFAULT: bir `AlgorithmIdentifier` (SEQUENCE) varsa
  // algoritmadır, yoksa üç indeks doğrudan gelir.
  const first = fields[0]
  const hasAlgorithm = fields.length === 4
  if (fields.length !== 3 && fields.length !== 4) {
    throw new SigningError(
      `ATSHashIndex üç ya da dört alanlı olmalı; ${String(fields.length)} var.`,
    )
  }
  const hashAlgorithmOid =
    hasAlgorithm && first !== undefined ? asOid(asSequence(first)[0] ?? first) : SHA256_OID

  const offset = hasAlgorithm ? 1 : 0
  const list = (at: number): readonly Uint8Array[] => {
    const node = fields[at]
    if (node === undefined) throw new SigningError('ATSHashIndex alanı eksik.')
    return asSequence(node).map((item) => asOctetString(item))
  }

  return {
    hashAlgorithmOid,
    certificatesHashIndex: list(offset),
    crlsHashIndex: list(offset + 1),
    unsignedAttrsHashIndex: list(offset + 2),
  }
}

/**
 * Arşiv damgasının `messageImprint` girdisini üretir — TS 101 733 §6.4.3.
 *
 * Standardın listelediği sıra, birebir:
 *
 * 1. `SignedData.encapContentInfo.eContentType`
 * 2. **İmzalanan verinin ÖZETİ** — verinin kendisi değil. Özet,
 *    `message-digest` imzalı özniteliğinin hesaplandığı içerik üzerinde,
 *    **arşiv damgasının** özet algoritmasıyla alınır (imzanınkiyle
 *    değil).
 * 3. `SignerInfo`nun `version`, `sid`, `digestAlgorithm`, `signedAttrs`,
 *    `signatureAlgorithm`, `signature` alanları, görünme sıralarıyla
 * 4. Tek bir `ATSHashIndex`
 *
 * @param components - {@link readArchiveComponents} çıktısı
 * @param atsHashIndex - {@link buildAtsHashIndex} çıktısı
 * @param hash - Arşiv damgasının özet algoritması
 * @param detachedContent - Ayrık imzada dışarıda tutulan veri
 * @returns Damgalanacak baytlar
 * @throws {SigningError} Ayrık imzada içerik verilmezse
 */
export const archiveTimestampInput = (
  components: ArchiveComponents,
  atsHashIndex: Uint8Array,
  hash: CmsDigest = 'sha256',
  detachedContent?: Uint8Array,
): Uint8Array => {
  const content = components.content ?? detachedContent
  if (content === undefined) {
    throw new SigningError(
      'Ayrık imzada arşiv damgası için içerik gerekli: girdinin ikinci bileşeni ' +
        'imzalanan verinin özetidir.',
    )
  }
  const contentDigest = new Uint8Array(createHash(hash).update(content).digest())

  return concat(components.eContentTypeDer, contentDigest, ...components.signerFields, atsHashIndex)
}

/** {@link checkAtsHashIndex} sonucu. */
export type AtsHashIndexCheck =
  { readonly complete: true } | { readonly complete: false; readonly reason: string }

/**
 * İndeksin belgedeki bileşenleri gerçekten karşıladığını denetler.
 *
 * §6.4.2: doğrularken bütün sertifikaların, iptal verilerinin ve
 * imzalanmamış özniteliklerin özetleri **yeniden hesaplanır**; yalnızca
 * indekste eşleşenler o damgayla korunmuş sayılır. Bu denetim olmadan
 * "damga geçerli" demek, damganın neyi kapsadığını söylememek olur —
 * saldırgan indekse girmemiş bir bileşeni sonradan ekleyebilir.
 *
 * Arşiv damgasının KENDİ özniteliği indekste bulunmaz: damga eklendiğinde
 * indeks çoktan hesaplanmıştır. Bu yüzden hariç tutulan öznitelikler
 * çağıran tarafından bildirilir.
 *
 * @param index - Çözümlenmiş {@link AtsHashIndex}
 * @param components - Belgedeki güncel bileşenler
 * @param hash - İndeksin özet algoritması
 * @param exclude - İndekste bulunması BEKLENMEYEN öznitelikler (ham DER)
 * @returns Eksiksizse `complete: true`
 */
export const checkAtsHashIndex = (
  index: AtsHashIndex,
  components: ArchiveComponents,
  hash: CmsDigest,
  exclude: readonly Uint8Array[] = [],
): AtsHashIndexCheck => {
  const digest = (bytes: Uint8Array): string =>
    toHex(new Uint8Array(createHash(hash).update(bytes).digest()))
  const excluded = new Set(exclude.map((item) => toHex(item)))

  const compare = (
    name: string,
    present: readonly Uint8Array[],
    indexed: readonly Uint8Array[],
  ): string | undefined => {
    const expected = present
      .filter((item) => !excluded.has(toHex(item)))
      .map(digest)
      .sort()
    const actual = indexed.map((item) => toHex(item)).sort()
    if (expected.length !== actual.length) {
      return `${name}: ${String(expected.length)} bileşen var, indekste ${String(actual.length)} kayıt.`
    }
    for (let i = 0; i < expected.length; i += 1) {
      if (expected[i] !== actual[i]) return `${name}: indeks belgedeki bileşenlerle eşleşmiyor.`
    }
    return undefined
  }

  const reason =
    compare('certificates', components.certificateInstances, index.certificatesHashIndex) ??
    compare('crls', components.crlInstances, index.crlsHashIndex) ??
    compare('unsignedAttrs', components.unsignedAttributeInstances, index.unsignedAttrsHashIndex)
  return reason === undefined ? { complete: true } : { complete: false, reason }
}

/** OID → `CmsDigest`; tanınmayan algoritma `undefined`. */
export const digestFromOid = (oid: string): CmsDigest | undefined =>
  (Object.keys(DIGEST_OID) as CmsDigest[]).find((key) => DIGEST_OID[key] === oid)
