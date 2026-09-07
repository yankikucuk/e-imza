import { deflateRawSync, inflateRawSync } from 'node:zlib'

import { concat, fromUtf8, utf8 } from '../core/bytes.js'

import { crc32 } from './crc32.js'

/**
 * En küçük ZIP okuyucu ve yazıcı — ASiC konteynerleri için.
 *
 * Kapsam kasten dar: ASiC'in ihtiyacı olan kadarı. Şifreleme, çok parçalı
 * arşiv ve ZIP64 desteklenmiyor; ASiC konteynerleri bunları kullanmaz ve
 * "belki lazım olur" diye eklemek, sınanmamış kod demektir.
 *
 * İki kural ASiC için hayati:
 * - `mimetype` girdisi **ilk** olmalı ve **sıkıştırılmamış** yazılmalı,
 * - onda ek alan (`extra field`) bulunmamalı.
 *
 * Bunlar sayesinde konteynerin türü, dosyanın ilk 38 baytına bakılarak —
 * ZIP'i açmadan — anlaşılabiliyor.
 */

/** Arşivdeki bir girdi. */
export interface ZipEntry {
  /** Dosya adı; ZIP'te her zaman eğik çizgiyle ayrılır. */
  readonly name: string
  /** Açılmış içerik. */
  readonly data: Uint8Array
  /** Sıkıştırılmadan mı yazılsın. */
  readonly stored?: boolean
}

const LOCAL_SIGNATURE = 0x04034b50
const CENTRAL_SIGNATURE = 0x02014b50
const EOCD_SIGNATURE = 0x06054b50

/** Küçük-endian 16 bit yazar. */
const u16 = (value: number): Uint8Array => new Uint8Array([value & 0xff, (value >>> 8) & 0xff])

/** Küçük-endian 32 bit yazar. */
const u32 = (value: number): Uint8Array =>
  new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff])

/** Küçük-endian 16 bit okur. */
const readU16 = (bytes: Uint8Array, at: number): number =>
  (bytes[at] ?? 0) | ((bytes[at + 1] ?? 0) << 8)

/** Küçük-endian 32 bit okur. */
const readU32 = (bytes: Uint8Array, at: number): number =>
  ((bytes[at] ?? 0) |
    ((bytes[at + 1] ?? 0) << 8) |
    ((bytes[at + 2] ?? 0) << 16) |
    ((bytes[at + 3] ?? 0) << 24)) >>>
  0

/**
 * MS-DOS tarih ve saat alanları.
 *
 * ZIP, 1980 öncesini temsil edemez. Sabit bir değer kullanmak çıktıyı
 * **deterministik** kılıyor: aynı girdi her zaman bayt bayt aynı arşivi
 * üretiyor ve testler karşılaştırılabilir kalıyor.
 */
const DOS_TIME = 0
const DOS_DATE = 0x0021 // 1980-01-01

/**
 * ZIP arşivi üretir.
 *
 * @param entries - Yazılacak girdiler, verilen sırayla
 * @returns Arşiv baytları
 */
export const createZip = (entries: readonly ZipEntry[]): Uint8Array => {
  const locals: Uint8Array[] = []
  const centrals: Uint8Array[] = []
  let offset = 0

  for (const entry of entries) {
    const name = utf8(entry.name)
    const stored = entry.stored ?? false
    const compressed = stored ? entry.data : new Uint8Array(deflateRawSync(Buffer.from(entry.data)))
    const checksum = crc32(entry.data)

    const local = concat(
      u32(LOCAL_SIGNATURE),
      u16(20), // gereken sürüm: 2.0
      u16(0), // bayrak yok
      u16(stored ? 0 : 8),
      u16(DOS_TIME),
      u16(DOS_DATE),
      u32(checksum),
      u32(compressed.length),
      u32(entry.data.length),
      u16(name.length),
      u16(0), // ek alan yok — ASiC `mimetype` için ŞART
      name,
    )
    locals.push(local, compressed)

    centrals.push(
      concat(
        u32(CENTRAL_SIGNATURE),
        u16(20), // üreten sürüm
        u16(20), // gereken sürüm
        u16(0),
        u16(stored ? 0 : 8),
        u16(DOS_TIME),
        u16(DOS_DATE),
        u32(checksum),
        u32(compressed.length),
        u32(entry.data.length),
        u16(name.length),
        u16(0), // ek alan
        u16(0), // yorum
        u16(0), // başlangıç diski
        u16(0), // iç öznitelikler
        u32(0), // dış öznitelikler
        u32(offset),
        name,
      ),
    )
    offset += local.length + compressed.length
  }

  const directory = concat(...centrals)
  return concat(
    ...locals,
    directory,
    u32(EOCD_SIGNATURE),
    u16(0),
    u16(0),
    u16(entries.length),
    u16(entries.length),
    u32(directory.length),
    u32(offset),
    u16(0), // arşiv yorumu yok
  )
}

/**
 * ZIP arşivini okur.
 *
 * Merkezî dizin üzerinden okunuyor — yerel başlıkları taramak yerine.
 * İkisi çelişebilir ve **merkezî dizin yetkilidir**; yerel başlıklara
 * güvenen okuyucular, arşive gizli girdi saklamaya açık olur.
 *
 * @param bytes - Arşiv baytları
 * @returns Girdiler, merkezî dizindeki sırayla
 * @throws {SyntaxError} Arşiv okunamazsa
 */
export const readZip = (bytes: Uint8Array): readonly ZipEntry[] => {
  const eocd = findEndOfCentralDirectory(bytes)
  const count = readU16(bytes, eocd + 10)
  let cursor = readU32(bytes, eocd + 16)

  const entries: ZipEntry[] = []
  for (let i = 0; i < count; i += 1) {
    if (readU32(bytes, cursor) !== CENTRAL_SIGNATURE) {
      throw new SyntaxError('ZIP: merkezî dizin girdisi bozuk.')
    }
    const method = readU16(bytes, cursor + 10)
    const compressedSize = readU32(bytes, cursor + 20)
    const uncompressedSize = readU32(bytes, cursor + 24)
    const nameLength = readU16(bytes, cursor + 28)
    const extraLength = readU16(bytes, cursor + 30)
    const commentLength = readU16(bytes, cursor + 32)
    const localOffset = readU32(bytes, cursor + 42)
    const name = fromUtf8(bytes.subarray(cursor + 46, cursor + 46 + nameLength))

    if (readU32(bytes, localOffset) !== LOCAL_SIGNATURE) {
      throw new SyntaxError(`ZIP: "${name}" için yerel başlık bulunamadı.`)
    }
    // Veri, yerel başlığın SONRASINDA başlar; yerel başlıktaki ad ve ek
    // alan uzunlukları merkezî dizindekinden farklı olabilir.
    const localNameLength = readU16(bytes, localOffset + 26)
    const localExtraLength = readU16(bytes, localOffset + 28)
    const start = localOffset + 30 + localNameLength + localExtraLength
    const raw = bytes.subarray(start, start + compressedSize)

    let data: Uint8Array
    if (method === 0) {
      data = raw
    } else if (method === 8) {
      data = new Uint8Array(inflateRawSync(Buffer.from(raw)))
    } else {
      throw new SyntaxError(`ZIP: desteklenmeyen sıkıştırma yöntemi: ${String(method)}`)
    }
    if (data.length !== uncompressedSize) {
      throw new SyntaxError(`ZIP: "${name}" açıldığında beklenen boyutta değil.`)
    }

    entries.push({ name, data, stored: method === 0 })
    cursor += 46 + nameLength + extraLength + commentLength
  }
  return entries
}

/**
 * Merkezî dizin sonu kaydını bulur.
 *
 * Arşiv yorumu değişken uzunlukta olduğu için kayıt SONDAN aranıyor.
 */
const findEndOfCentralDirectory = (bytes: Uint8Array): number => {
  const minimum = 22
  if (bytes.length < minimum) throw new SyntaxError('ZIP: dosya çok küçük.')
  // Yorum en fazla 65535 bayt olabilir.
  const limit = Math.max(0, bytes.length - minimum - 0xffff)
  for (let i = bytes.length - minimum; i >= limit; i -= 1) {
    if (readU32(bytes, i) === EOCD_SIGNATURE) return i
  }
  throw new SyntaxError('ZIP: merkezî dizin sonu bulunamadı.')
}

/**
 * Arşivin ilk girdisini, ZIP'i tam olarak açmadan okur.
 *
 * ASiC'in tür tespiti buna dayanıyor: `mimetype` girdisi ilk ve
 * sıkıştırılmamış olduğu için içeriği doğrudan okunabiliyor.
 *
 * @param bytes - Arşiv baytları
 * @returns İlk girdinin adı ve ham içeriği; okunamazsa `undefined`
 */
export const peekFirstEntry = (
  bytes: Uint8Array,
): { readonly name: string; readonly data: Uint8Array } | undefined => {
  if (bytes.length < 30 || readU32(bytes, 0) !== LOCAL_SIGNATURE) return undefined
  const method = readU16(bytes, 8)
  if (method !== 0) return undefined
  const size = readU32(bytes, 18)
  const nameLength = readU16(bytes, 26)
  const extraLength = readU16(bytes, 28)
  const name = fromUtf8(bytes.subarray(30, 30 + nameLength))
  const start = 30 + nameLength + extraLength
  if (start + size > bytes.length) return undefined
  return { name, data: bytes.subarray(start, start + size) }
}
