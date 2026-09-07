import { concat } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

/**
 * ASN.1 DER okuyucu ve yazıcı.
 *
 * Kapsam kasten dardır: X.509, PKCS#12, PKCS#8 ve CMS'in kullandığı
 * kodlamalar. BER'in belirsiz uzunluk (`indefinite length`) biçimi kabul
 * edilmez — DER onu zaten yasaklar ve imza doğrulayan bir kütüphanede
 * "esnek olalım" demek, aynı baytların iki farklı biçimde okunabilmesi
 * demektir.
 */

/** ASN.1 etiket sınıfı. */
export type DerTagClass = 'universal' | 'application' | 'context' | 'private'

/** Sık kullanılan evrensel etiket numaraları. */
export const DerTag = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OBJECT_IDENTIFIER: 6,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  PRINTABLE_STRING: 19,
  T61_STRING: 20,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  BMP_STRING: 30,
} as const

/**
 * Çözümlenmiş bir DER düğümü.
 *
 * {@link raw} alanı kritiktir: sertifikanın özeti, CMS'in imzalanmış
 * öznitelikleri ve zaman damgası jetonu, hepsi **kaynaktaki baytlar
 * üzerinden** hesaplanır. Düğümü yeniden kodlayıp özetlemek, kaynağın
 * DER'e tam uymadığı durumlarda (ki gerçek sertifikalarda görülür) farklı
 * bir özet üretir ve imza tutmaz.
 */
export interface DerNode {
  readonly tagClass: DerTagClass
  readonly constructed: boolean
  readonly tagNumber: number
  /** Yalnızca içerik oktetleri (başlık hariç). */
  readonly content: Uint8Array
  /** Kurgusal düğümlerin alt düğümleri; ilkel düğümlerde boş. */
  readonly children: readonly DerNode[]
  /** Başlık dâhil tüm TLV — kaynaktaki hâliyle. */
  readonly raw: Uint8Array
}

const CLASS_BY_BITS: readonly DerTagClass[] = ['universal', 'application', 'context', 'private']

/**
 * İzin verilen en fazla iç içe geçme derinliği.
 *
 * Gerçek X.509 ve PKCS#12 yapıları on beş seviyeyi geçmez; 64 bol bir
 * paydır. Sınırın kendisi güvenlik gereğidir: `SEQUENCE` başlıkları
 * sadece iki bayt olduğu için ~20 KB'lık bir girdiyle on binlerce seviye
 * derinlik kurulabilir ve özyinelemeli bir ayrıştırıcı yığını taşırır.
 * Süreç çöker; hizmet durur.
 *
 * Aynı sınıf açık `PKI.js#466`de (CVSS 8.7) bildirildi. Ölçüldü (Eylül
 * 2026): `asn1js` 3.0.10 bu sınırı zaten eklemiş (`DEFAULT_MAX_DEPTH = 100`)
 * — 100 seviye geçiyor, 1.000 seviye reddediliyor. Yani bu bir üstünlük
 * değil, en baştan doğru yapılmış olan şey; kaydı, ileride sınırın
 * "gereksiz" diye kaldırılmaması için burada duruyor.
 */
const MAX_DEPTH = 64

/**
 * Tek bir DER değerini çözümler.
 *
 * @param bytes - Kaynak baytlar
 * @param offset - Başlangıç konumu; varsayılan 0
 * @param depth - İç kullanım: geçerli iç içe geçme derinliği
 * @returns Düğüm ve bir sonraki değerin başlangıç konumu
 * @throws {DerParseError} Baytlar geçerli DER değilse ya da derinlik aşılırsa
 */
export const decodeDerAt = (
  bytes: Uint8Array,
  offset = 0,
  depth = 0,
): { readonly node: DerNode; readonly next: number } => {
  if (depth > MAX_DEPTH) {
    throw new DerParseError(offset, `İç içe geçme sınırı aşıldı (${String(MAX_DEPTH)}).`)
  }
  const start = offset
  if (offset >= bytes.length) throw new DerParseError(offset, 'Beklenmedik son.')

  const identifier = bytes[offset] ?? 0
  offset += 1
  const tagClass = CLASS_BY_BITS[(identifier >> 6) & 0b11] ?? 'universal'
  const constructed = (identifier & 0b0010_0000) !== 0
  let tagNumber = identifier & 0b0001_1111
  if (tagNumber === 31) {
    // Çok baytlı etiket numarası: 7 bitlik gruplar, son bayta kadar üst bit 1.
    tagNumber = 0
    for (;;) {
      if (offset >= bytes.length) throw new DerParseError(offset, 'Yarım kalmış etiket numarası.')
      const byte = bytes[offset] ?? 0
      offset += 1
      tagNumber = tagNumber * 128 + (byte & 0x7f)
      if ((byte & 0x80) === 0) break
      if (tagNumber > Number.MAX_SAFE_INTEGER) {
        throw new DerParseError(offset, 'Etiket numarası çok büyük.')
      }
    }
  }

  if (offset >= bytes.length) throw new DerParseError(offset, 'Uzunluk baytı yok.')
  const first = bytes[offset] ?? 0
  offset += 1
  let length: number
  if (first === 0x80) {
    throw new DerParseError(offset - 1, "Belirsiz uzunluk DER'de geçersizdir.")
  }
  if ((first & 0x80) === 0) {
    length = first
  } else {
    const count = first & 0x7f
    if (count > 4) throw new DerParseError(offset - 1, 'Uzunluk alanı çok geniş.')
    length = 0
    for (let i = 0; i < count; i += 1) {
      if (offset >= bytes.length) throw new DerParseError(offset, 'Yarım kalmış uzunluk.')
      length = length * 256 + (bytes[offset] ?? 0)
      offset += 1
    }
  }

  const end = offset + length
  if (end > bytes.length) {
    throw new DerParseError(offset, `Uzunluk kaynağı aşıyor: ${String(length)} bayt istendi.`)
  }
  const content = bytes.subarray(offset, end)

  const children: DerNode[] = []
  if (constructed) {
    let cursor = 0
    while (cursor < content.length) {
      const parsed = decodeDerAt(content, cursor, depth + 1)
      children.push(parsed.node)
      cursor = parsed.next
    }
  }

  return {
    node: { tagClass, constructed, tagNumber, content, children, raw: bytes.subarray(start, end) },
    next: end,
  }
}

/**
 * Baytların tamamının tek bir DER değeri olduğunu varsayarak çözümler.
 *
 * @param bytes - Kaynak baytlar
 * @returns Kök düğüm
 * @throws {DerParseError} Baytlar tükenmemişse ya da geçerli DER değilse
 */
export const decodeDer = (bytes: Uint8Array): DerNode => {
  const { node, next } = decodeDerAt(bytes, 0)
  if (next !== bytes.length) {
    throw new DerParseError(next, `Değerden sonra ${String(bytes.length - next)} artık bayt var.`)
  }
  return node
}

/* ── Okuma yardımcıları ───────────────────────────────────────────────── */

/** Düğümün beklenen evrensel etikete sahip olduğunu doğrular. */
const expectUniversal = (node: DerNode, tagNumber: number, what: string): DerNode => {
  if (node.tagClass !== 'universal' || node.tagNumber !== tagNumber) {
    throw new DerParseError(
      0,
      `${what} bekleniyordu; ${node.tagClass}/${String(node.tagNumber)} bulundu.`,
    )
  }
  return node
}

/**
 * `SEQUENCE` düğümünün alt düğümlerini verir.
 *
 * @param node - Beklenen `SEQUENCE`
 * @returns Alt düğümler
 * @throws {DerParseError} Düğüm `SEQUENCE` değilse
 */
export const asSequence = (node: DerNode): readonly DerNode[] =>
  expectUniversal(node, DerTag.SEQUENCE, 'SEQUENCE').children

/**
 * `SET` düğümünün alt düğümlerini verir.
 *
 * @param node - Beklenen `SET`
 * @returns Alt düğümler
 * @throws {DerParseError} Düğüm `SET` değilse
 */
export const asSet = (node: DerNode): readonly DerNode[] =>
  expectUniversal(node, DerTag.SET, 'SET').children

/**
 * `INTEGER` değerini `bigint` olarak verir.
 *
 * Sertifika seri numaraları 20 bayta kadar çıkabildiği için `number`
 * kullanılmaz; `xadesjs#52` seri numarasını onaltılık dize olarak yazdığı
 * için dışarıdaki doğrulayıcılar tarafından reddediliyordu — doğru tip,
 * doğru gösterimin ön koşuludur.
 *
 * @param node - Beklenen `INTEGER`
 * @returns İşaretli tam sayı değeri
 */
export const asInteger = (node: DerNode): bigint => {
  expectUniversal(node, DerTag.INTEGER, 'INTEGER')
  const bytes = node.content
  if (bytes.length === 0) throw new DerParseError(0, 'Boş INTEGER.')
  const negative = ((bytes[0] ?? 0) & 0x80) !== 0
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  if (!negative) return value
  // İki'ye tümleyen: 2^(8n) çıkararak işaretli değere dön.
  return value - (1n << BigInt(bytes.length * 8))
}

/**
 * `OBJECT IDENTIFIER` değerini noktalı gösterimle verir.
 *
 * @param node - Beklenen `OBJECT IDENTIFIER`
 * @returns `1.2.840.113549.1.1.11` biçiminde OID
 */
export const asOid = (node: DerNode): string => {
  expectUniversal(node, DerTag.OBJECT_IDENTIFIER, 'OBJECT IDENTIFIER')
  const bytes = node.content
  if (bytes.length === 0) throw new DerParseError(0, 'Boş OID.')
  const parts: string[] = []
  const first = bytes[0] ?? 0
  // İlk iki bileşen tek bayta sıkıştırılmıştır: 40 * x + y.
  parts.push(String(Math.floor(first / 40)), String(first % 40))
  let value = 0n
  let started = false
  for (let i = 1; i < bytes.length; i += 1) {
    const byte = bytes[i] ?? 0
    value = (value << 7n) | BigInt(byte & 0x7f)
    started = true
    if ((byte & 0x80) === 0) {
      parts.push(value.toString())
      value = 0n
      started = false
    }
  }
  if (started) throw new DerParseError(bytes.length, 'Yarım kalmış OID bileşeni.')
  return parts.join('.')
}

/**
 * `OCTET STRING` içeriğini verir.
 *
 * Kurgusal (parçalara bölünmüş) `OCTET STRING` de kabul edilir ve parçalar
 * birleştirilir. DER bölünmeye izin vermez, ama sahadaki dosyalar her zaman
 * DER değildir: `PKI.js#405` tam olarak bu — pkijs'in ürettiği PKCS#12
 * kapları içeriği 1024 baytlık parçalara bölüyor ve katı okuyucular o
 * dosyaları açamıyor. Okurken hoşgörülü olmak, yazarken katı kalmak
 * (biz her zaman ilkel yazarız) doğru dengedir.
 *
 * @param node - Beklenen `OCTET STRING`
 * @returns İçerik baytları; bölünmüşse birleştirilmiş hâli
 */
export const asOctetString = (node: DerNode): Uint8Array => {
  const octetString = expectUniversal(node, DerTag.OCTET_STRING, 'OCTET STRING')
  if (!octetString.constructed) return octetString.content
  return concat(...octetString.children.map((child) => asOctetString(child)))
}

/**
 * `BIT STRING` içeriğini verir (kullanılmayan bit sayısı baytı atılır).
 *
 * @param node - Beklenen `BIT STRING`
 * @returns Bit dizisinin bayt gösterimi
 * @throws {DerParseError} Kullanılmayan bit sayısı 0 değilse — anahtar ve
 *   imza yapılarında her zaman 0'dır; değilse yapı beklenenden farklıdır.
 */
export const asBitString = (node: DerNode): Uint8Array => {
  expectUniversal(node, DerTag.BIT_STRING, 'BIT STRING')
  const unused = node.content[0] ?? 0
  if (unused !== 0) throw new DerParseError(0, `Beklenmedik dolgu biti: ${String(unused)}`)
  return node.content.subarray(1)
}

/**
 * Metin türündeki düğümü dizeye çevirir.
 *
 * `BMPString` UTF-16BE, `UTF8String` UTF-8, kalanlar Latin-1 olarak okunur.
 * Latin-1 varsayımı `PrintableString` ve `IA5String` için doğrudur;
 * `TeletexString` teoride farklıdır ama gerçek sertifikalarda Latin-1
 * yazılır ve öyle okunması beklenir.
 *
 * @param node - Metin düğümü
 * @returns Çözülmüş dize
 */
export const asString = (node: DerNode): string => {
  if (node.tagNumber === DerTag.BMP_STRING) {
    let out = ''
    for (let i = 0; i + 1 < node.content.length; i += 2) {
      out += String.fromCharCode(((node.content[i] ?? 0) << 8) | (node.content[i + 1] ?? 0))
    }
    return out
  }
  if (node.tagNumber === DerTag.UTF8_STRING) return new TextDecoder().decode(node.content)
  let out = ''
  for (const byte of node.content) out += String.fromCharCode(byte)
  return out
}

/**
 * `UTCTime` ya da `GeneralizedTime` değerini `Date`'e çevirir.
 *
 * `UTCTime` iki haneli yıl taşır; RFC 5280 §4.1.2.5.1 uyarınca 50 ve üstü
 * 19xx, altı 20xx sayılır.
 *
 * @param node - Zaman düğümü
 * @returns UTC zaman damgası
 */
export const asTime = (node: DerNode): Date => {
  const text = asString(node)
  const match =
    node.tagNumber === DerTag.UTC_TIME
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(text)
      : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(text)
  if (match === null) throw new DerParseError(0, `Çözümlenemeyen zaman değeri: ${text}`)
  const rawYear = Number.parseInt(match[1] ?? '0', 10)
  const year =
    node.tagNumber === DerTag.UTC_TIME ? (rawYear >= 50 ? 1900 + rawYear : 2000 + rawYear) : rawYear
  return new Date(
    Date.UTC(
      year,
      Number.parseInt(match[2] ?? '1', 10) - 1,
      Number.parseInt(match[3] ?? '1', 10),
      Number.parseInt(match[4] ?? '0', 10),
      Number.parseInt(match[5] ?? '0', 10),
      Number.parseInt(match[6] ?? '0', 10),
    ),
  )
}

/**
 * Bağlama özgü etiketli (`[n]`) bir düğümü arar.
 *
 * @param nodes - Aranacak düğümler
 * @param tagNumber - Etiket numarası
 * @returns Bulunan düğüm ya da `undefined`
 */
export const findContext = (nodes: readonly DerNode[], tagNumber: number): DerNode | undefined =>
  nodes.find((node) => node.tagClass === 'context' && node.tagNumber === tagNumber)

/* ── Yazma ────────────────────────────────────────────────────────────── */

/** DER uzunluk alanını kodlar (her zaman en kısa biçim). */
const encodeLength = (length: number): Uint8Array => {
  if (length < 0x80) return new Uint8Array([length])
  const bytes: number[] = []
  let remaining = length
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff)
    remaining = Math.floor(remaining / 256)
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes])
}

/** Etiket baytını üretir; 31 ve üstü etiket numaraları bu pakette geçmez. */
const encodeIdentifier = (
  tagClass: DerTagClass,
  constructed: boolean,
  tagNumber: number,
): Uint8Array => {
  if (tagNumber >= 31) throw new DerParseError(0, 'Çok baytlı etiket yazımı desteklenmiyor.')
  const classBits = CLASS_BY_BITS.indexOf(tagClass) << 6
  return new Uint8Array([classBits | (constructed ? 0x20 : 0) | tagNumber])
}

/**
 * Ham bir TLV üretir.
 *
 * @param tagClass - Etiket sınıfı
 * @param constructed - Kurgusal mı
 * @param tagNumber - Etiket numarası
 * @param content - İçerik oktetleri
 * @returns Başlık dâhil kodlanmış değer
 */
export const encodeDer = (
  tagClass: DerTagClass,
  constructed: boolean,
  tagNumber: number,
  content: Uint8Array,
): Uint8Array =>
  concat(encodeIdentifier(tagClass, constructed, tagNumber), encodeLength(content.length), content)

/** `SEQUENCE` üretir. */
export const derSequence = (...items: readonly Uint8Array[]): Uint8Array =>
  encodeDer('universal', true, DerTag.SEQUENCE, concat(...items))

/**
 * `SET OF` üretir; öğeler DER kuralına göre sıralanır.
 *
 * DER, `SET OF` öğelerinin kodlanmış hâllerine göre artan sırada yazılmasını
 * ŞART koşar. CMS'in `signedAttrs` alanı bir `SET OF`'tur ve imza tam olarak
 * bu kodlama üzerinden hesaplanır — sıralamayı atlayan bir uygulama kendi
 * doğrulayıcısıyla çalışır, başkasınınkiyle çalışmaz (`PKI.js#402` aynı
 * ailedeki bir hata).
 */
export const derSetOf = (...items: readonly Uint8Array[]): Uint8Array => {
  const sorted = [...items].sort((a, b) => {
    const shared = Math.min(a.length, b.length)
    for (let i = 0; i < shared; i += 1) {
      const difference = (a[i] ?? 0) - (b[i] ?? 0)
      if (difference !== 0) return difference
    }
    return a.length - b.length
  })
  return encodeDer('universal', true, DerTag.SET, concat(...sorted))
}

/**
 * Bağlama özgü açık (`EXPLICIT [n]`) sarmalayıcı üretir.
 *
 * @param tagNumber - Etiket numarası
 * @param items - Sarmalanacak kodlanmış değerler
 */
export const derExplicit = (tagNumber: number, ...items: readonly Uint8Array[]): Uint8Array =>
  encodeDer('context', true, tagNumber, concat(...items))

/**
 * Hazır kodlanmış bir yapının dış ETİKETİNİ bağlama özgü örtük
 * (`IMPLICIT [n]`) etikete çevirir.
 *
 * CMS'in `signedAttrs` alanı için var. İmza `SET` biçiminin üzerinde
 * hesaplanır, iletimde ise `[0] IMPLICIT` yazılır; ikisi yalnızca ilk
 * BAYTTA ayrılır. Yapıyı yeniden kodlamak yerine baytı değiştirmek,
 * imzalanan ile gömülen arasında bir bayt farkı olma riskini ortadan
 * kaldırıyor.
 *
 * @param tagNumber - Etiket numarası
 * @param encoded - Kodlanmış yapı (kurgusal bir tür olmalı)
 * @returns Aynı içerik, yeni dış etiketle
 */
export const derImplicitSet = (tagNumber: number, encoded: Uint8Array): Uint8Array => {
  const out = new Uint8Array(encoded)
  out[0] = 0xa0 | tagNumber
  return out
}

/** `BOOLEAN` üretir. */
export const derBoolean = (value: boolean): Uint8Array =>
  encodeDer('universal', false, DerTag.BOOLEAN, new Uint8Array([value ? 0xff : 0x00]))

/** `INTEGER` üretir. */
export const derInteger = (value: bigint): Uint8Array => {
  if (value === 0n) return encodeDer('universal', false, DerTag.INTEGER, new Uint8Array([0]))
  const negative = value < 0n
  const bytes: number[] = []
  if (negative) {
    // İki'ye tümleyen gösterime çevir: yeterli genişlikte 2^(8n) ekle.
    let width = 1
    while (value < -(1n << BigInt(width * 8 - 1))) width += 1
    let magnitude = value + (1n << BigInt(width * 8))
    for (let i = 0; i < width; i += 1) {
      bytes.unshift(Number(magnitude & 0xffn))
      magnitude >>= 8n
    }
  } else {
    let magnitude = value
    while (magnitude > 0n) {
      bytes.unshift(Number(magnitude & 0xffn))
      magnitude >>= 8n
    }
    // Üst bit 1 ise pozitifliği korumak için başa sıfır bayt eklenir.
    if (((bytes[0] ?? 0) & 0x80) !== 0) bytes.unshift(0)
  }
  return encodeDer('universal', false, DerTag.INTEGER, new Uint8Array(bytes))
}

/** `OCTET STRING` üretir. */
export const derOctetString = (bytes: Uint8Array): Uint8Array =>
  encodeDer('universal', false, DerTag.OCTET_STRING, bytes)

/** `BIT STRING` üretir (kullanılmayan bit sayısı 0). */
export const derBitString = (bytes: Uint8Array): Uint8Array =>
  encodeDer('universal', false, DerTag.BIT_STRING, concat(new Uint8Array([0]), bytes))

/** `NULL` üretir. */
export const derNull = (): Uint8Array =>
  encodeDer('universal', false, DerTag.NULL, new Uint8Array(0))

/** `UTF8String` üretir. */
export const derUtf8String = (text: string): Uint8Array =>
  encodeDer('universal', false, DerTag.UTF8_STRING, new TextEncoder().encode(text))

/** `GeneralizedTime` üretir — CMS `signingTime` her zaman UTC'dir. */
export const derGeneralizedTime = (date: Date): Uint8Array => {
  const pad = (value: number, width = 2): string => String(value).padStart(width, '0')
  const text =
    `${pad(date.getUTCFullYear(), 4)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
  return encodeDer('universal', false, DerTag.GENERALIZED_TIME, new TextEncoder().encode(text))
}

/**
 * `UTCTime` üretir.
 *
 * RFC 5652 §11.3: 1 Ocak 1950 ile 31 Aralık 2049 arasındaki tarihler
 * `UTCTime` olarak kodlanmak ZORUNDA. `GeneralizedTime` yazmak bugünün
 * tarihleri için standart dışıdır ve katı doğrulayıcılar reddeder.
 *
 * @param date - Kodlanacak zaman
 * @returns `UTCTime` kodlaması
 * @throws {DerParseError} Tarih UTCTime aralığının dışındaysa
 */
export const derUtcTime = (date: Date): Uint8Array => {
  const year = date.getUTCFullYear()
  if (year < 1950 || year > 2049) {
    throw new DerParseError(0, `UTCTime aralığı dışında: ${String(year)}`)
  }
  const pad = (value: number): string => String(value).padStart(2, '0')
  const text =
    `${pad(year % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
  return encodeDer('universal', false, DerTag.UTC_TIME, new TextEncoder().encode(text))
}

/**
 * Noktalı OID gösterimini kodlar.
 *
 * @param oid - `1.2.840.113549.1.1.11` biçiminde OID
 * @returns Kodlanmış `OBJECT IDENTIFIER`
 * @throws {DerParseError} Gösterim geçersizse
 */
export const derOid = (oid: string): Uint8Array => {
  const parts = oid.split('.').map((part) => {
    if (!/^\d+$/.test(part)) throw new DerParseError(0, `Geçersiz OID bileşeni: "${part}"`)
    return BigInt(part)
  })
  if (parts.length < 2) throw new DerParseError(0, `OID en az iki bileşen içermeli: "${oid}"`)
  const bytes: number[] = [Number((parts[0] ?? 0n) * 40n + (parts[1] ?? 0n))]
  for (const part of parts.slice(2)) {
    const group: number[] = []
    let value = part
    do {
      group.unshift(Number(value & 0x7fn))
      value >>= 7n
    } while (value > 0n)
    for (let i = 0; i < group.length - 1; i += 1) group[i] = (group[i] ?? 0) | 0x80
    bytes.push(...group)
  }
  return encodeDer('universal', false, DerTag.OBJECT_IDENTIFIER, new Uint8Array(bytes))
}
