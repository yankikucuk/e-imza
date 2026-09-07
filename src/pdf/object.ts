import { fromUtf8, utf8 } from '../core/bytes.js'

/**
 * PDF nesne modeli ve ayrıştırıcısı.
 *
 * Kapsam kasten dar: imza eklemek için gereken kadarı. İçerik akışları,
 * yazı tipleri ve görüntü süzgeçleri **okunmaz** — imza onlara dokunmaz,
 * dokunmaması da gerekir. PAdES artımlı güncelleme ile çalışır: özgün
 * baytlar bayt bayt korunur, yeni nesneler dosyanın SONUNA eklenir.
 *
 * Bu yüzden ayrıştırıcının görevi yalnızca şu: çapraz başvuru tablosunu ve
 * belge kökünü bulup, hangi nesnelerin üzerine yazılacağını anlamak.
 */

/** PDF nesne türleri. */
export type PdfObject =
  | { readonly kind: 'null' }
  | { readonly kind: 'boolean'; readonly value: boolean }
  | { readonly kind: 'number'; readonly value: number }
  | { readonly kind: 'string'; readonly value: Uint8Array; readonly hex: boolean }
  | { readonly kind: 'name'; readonly value: string }
  | { readonly kind: 'array'; readonly items: readonly PdfObject[] }
  | { readonly kind: 'dict'; readonly entries: ReadonlyMap<string, PdfObject> }
  | {
      readonly kind: 'stream'
      readonly entries: ReadonlyMap<string, PdfObject>
      /** Ham akış baytları — süzgeç UYGULANMAMIŞ hâliyle. */
      readonly raw: Uint8Array
    }
  | { readonly kind: 'ref'; readonly number: number; readonly generation: number }

/** PDF sözdiziminde boşluk sayılan baytlar. */
const isWhitespace = (byte: number): boolean =>
  byte === 0x00 || byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20

/** Sınırlayıcı baytlar — bir simgeyi sonlandırırlar. */
const isDelimiter = (byte: number): boolean =>
  byte === 0x28 || // (
  byte === 0x29 || // )
  byte === 0x3c || // <
  byte === 0x3e || // >
  byte === 0x5b || // [
  byte === 0x5d || // ]
  byte === 0x7b || // {
  byte === 0x7d || // }
  byte === 0x2f || // /
  byte === 0x25 // %

/** Düzenli karakter: ne boşluk ne sınırlayıcı. */
const isRegular = (byte: number): boolean => !isWhitespace(byte) && !isDelimiter(byte)

/** PDF nesnesi okuyan imleç. */
export class PdfReader {
  private position: number

  constructor(
    private readonly bytes: Uint8Array,
    start = 0,
  ) {
    this.position = start
  }

  /** Geçerli konum. */
  get offset(): number {
    return this.position
  }

  set offset(value: number) {
    this.position = value
  }

  /** Boşlukları ve yorumları atlar. */
  skipWhitespace(): void {
    while (this.position < this.bytes.length) {
      const byte = this.bytes[this.position] ?? 0
      if (isWhitespace(byte)) {
        this.position += 1
        continue
      }
      // Yorum: `%` işaretinden satır sonuna kadar.
      if (byte === 0x25) {
        while (
          this.position < this.bytes.length &&
          (this.bytes[this.position] ?? 0) !== 0x0a &&
          (this.bytes[this.position] ?? 0) !== 0x0d
        ) {
          this.position += 1
        }
        continue
      }
      break
    }
  }

  /** Sonraki simgeyi (anahtar sözcük ya da sayı) okur. */
  readToken(): string {
    this.skipWhitespace()
    const start = this.position
    while (this.position < this.bytes.length && isRegular(this.bytes[this.position] ?? 0)) {
      this.position += 1
    }
    if (start === this.position && this.position < this.bytes.length) {
      // Sınırlayıcı: tek bayt olarak döndür.
      this.position += 1
      return fromUtf8(this.bytes.subarray(start, this.position))
    }
    return fromUtf8(this.bytes.subarray(start, this.position))
  }

  /** Verilen dizeyle başlıyorsa tüketir. */
  consume(literal: string): boolean {
    this.skipWhitespace()
    const expected = utf8(literal)
    for (let i = 0; i < expected.length; i += 1) {
      if (this.bytes[this.position + i] !== expected[i]) return false
    }
    this.position += expected.length
    return true
  }

  /**
   * Bir PDF nesnesi okur.
   *
   * @returns Okunan nesne
   * @throws {SyntaxError} Sözdizimi tanınmazsa
   */
  readObject(): PdfObject {
    this.skipWhitespace()
    const byte = this.bytes[this.position]
    if (byte === undefined) throw new SyntaxError('PDF: beklenmedik dosya sonu.')

    if (byte === 0x2f) return this.readName()
    if (byte === 0x28) return this.readLiteralString()
    if (byte === 0x5b) return this.readArray()
    if (byte === 0x3c) {
      return (this.bytes[this.position + 1] ?? 0) === 0x3c
        ? this.readDictionaryOrStream()
        : this.readHexString()
    }

    const start = this.position
    const token = this.readToken()
    if (token === 'true') return { kind: 'boolean', value: true }
    if (token === 'false') return { kind: 'boolean', value: false }
    if (token === 'null') return { kind: 'null' }

    if (/^[+-]?[\d.]+$/.test(token)) {
      // `N G R` biçimi dolaylı başvurudur; ileriye bakarak ayırt edilir.
      const save = this.position
      if (/^\d+$/.test(token)) {
        const second = this.readToken()
        if (/^\d+$/.test(second)) {
          const third = this.readToken()
          if (third === 'R') {
            return {
              kind: 'ref',
              number: Number.parseInt(token, 10),
              generation: Number.parseInt(second, 10),
            }
          }
        }
      }
      this.position = save
      return { kind: 'number', value: Number.parseFloat(token) }
    }

    this.position = start
    throw new SyntaxError(`PDF: tanınmayan nesne (konum ${String(start)}): "${token}"`)
  }

  /** `/Ad` — `#XX` kaçışları çözülür. */
  private readName(): PdfObject {
    this.position += 1
    let out = ''
    while (this.position < this.bytes.length && isRegular(this.bytes[this.position] ?? 0)) {
      const byte = this.bytes[this.position] ?? 0
      if (byte === 0x23 && this.position + 2 < this.bytes.length) {
        const hex = fromUtf8(this.bytes.subarray(this.position + 1, this.position + 3))
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(Number.parseInt(hex, 16))
          this.position += 3
          continue
        }
      }
      out += String.fromCharCode(byte)
      this.position += 1
    }
    return { kind: 'name', value: out }
  }

  /** `(metin)` — iç içe parantezler ve ters eğik çizgi kaçışları. */
  private readLiteralString(): PdfObject {
    this.position += 1
    const out: number[] = []
    let depth = 1
    while (this.position < this.bytes.length) {
      const byte = this.bytes[this.position] ?? 0
      this.position += 1
      if (byte === 0x5c) {
        const next = this.bytes[this.position] ?? 0
        this.position += 1
        // `\n`, `\r`, `\t`, `\b`, `\f` kaçışları.
        const simple: Readonly<Record<number, number>> = {
          0x6e: 0x0a,
          0x72: 0x0d,
          0x74: 0x09,
          0x62: 0x08,
          0x66: 0x0c,
        }
        const mapped = simple[next]
        if (mapped !== undefined) out.push(mapped)
        else if (next >= 0x30 && next <= 0x37) {
          // Sekizlik: en fazla üç basamak.
          let value = next - 0x30
          for (let i = 0; i < 2; i += 1) {
            const digit = this.bytes[this.position] ?? 0
            if (digit < 0x30 || digit > 0x37) break
            value = value * 8 + (digit - 0x30)
            this.position += 1
          }
          out.push(value & 0xff)
        } else if (next !== 0x0a && next !== 0x0d) out.push(next)
        continue
      }
      if (byte === 0x28) depth += 1
      if (byte === 0x29) {
        depth -= 1
        if (depth === 0) break
      }
      out.push(byte)
    }
    return { kind: 'string', value: new Uint8Array(out), hex: false }
  }

  /** `<onaltılık>` */
  private readHexString(): PdfObject {
    this.position += 1
    let digits = ''
    while (this.position < this.bytes.length && (this.bytes[this.position] ?? 0) !== 0x3e) {
      const char = String.fromCharCode(this.bytes[this.position] ?? 0)
      if (/[0-9a-fA-F]/.test(char)) digits += char
      this.position += 1
    }
    this.position += 1
    if (digits.length % 2 === 1) digits += '0'
    const out = new Uint8Array(digits.length / 2)
    for (let i = 0; i < out.length; i += 1) {
      out[i] = Number.parseInt(digits.slice(i * 2, i * 2 + 2), 16)
    }
    return { kind: 'string', value: out, hex: true }
  }

  /** `[…]` */
  private readArray(): PdfObject {
    this.position += 1
    const items: PdfObject[] = []
    for (;;) {
      this.skipWhitespace()
      if (this.position >= this.bytes.length) throw new SyntaxError('PDF: kapanmamış dizi.')
      if ((this.bytes[this.position] ?? 0) === 0x5d) {
        this.position += 1
        break
      }
      items.push(this.readObject())
    }
    return { kind: 'array', items }
  }

  /** `<<…>>` ve ardından `stream` gelirse akış. */
  private readDictionaryOrStream(): PdfObject {
    this.position += 2
    const entries = new Map<string, PdfObject>()
    for (;;) {
      this.skipWhitespace()
      if (this.position >= this.bytes.length) throw new SyntaxError('PDF: kapanmamış sözlük.')
      if (
        (this.bytes[this.position] ?? 0) === 0x3e &&
        (this.bytes[this.position + 1] ?? 0) === 0x3e
      ) {
        this.position += 2
        break
      }
      const key = this.readObject()
      if (key.kind !== 'name') throw new SyntaxError('PDF: sözlük anahtarı ad olmalı.')
      entries.set(key.value, this.readObject())
    }

    const save = this.position
    this.skipWhitespace()
    if (this.consume('stream')) {
      // `stream` anahtar sözcüğünü CRLF ya da LF izler.
      if ((this.bytes[this.position] ?? 0) === 0x0d) this.position += 1
      if ((this.bytes[this.position] ?? 0) === 0x0a) this.position += 1
      const start = this.position
      const lengthEntry = entries.get('Length')
      // `/Length` dolaylı olabilir; o zaman `endstream` aranır.
      let end: number
      if (lengthEntry?.kind === 'number') {
        end = start + lengthEntry.value
      } else {
        end = indexOfSequence(this.bytes, utf8('endstream'), start)
        if (end === -1) throw new SyntaxError('PDF: kapanmamış akış.')
        // Sondaki satır sonu akışın parçası değil.
        if ((this.bytes[end - 1] ?? 0) === 0x0a) end -= 1
        if ((this.bytes[end - 1] ?? 0) === 0x0d) end -= 1
      }
      const raw = this.bytes.subarray(start, end)
      this.position = end
      this.skipWhitespace()
      this.consume('endstream')
      return { kind: 'stream', entries, raw }
    }
    this.position = save
    return { kind: 'dict', entries }
  }
}

/** Bayt dizisinde alt dizi arar. */
export const indexOfSequence = (haystack: Uint8Array, needle: Uint8Array, from = 0): number => {
  outer: for (let i = from; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

/** Bayt dizisinde alt diziyi SONDAN arar. */
export const lastIndexOfSequence = (haystack: Uint8Array, needle: Uint8Array): number => {
  outer: for (let i = haystack.length - needle.length; i >= 0; i -= 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return i
  }
  return -1
}

/** Sözlükten değer alır; sözlük ya da akış olabilir. */
export const dictEntry = (object: PdfObject, key: string): PdfObject | undefined =>
  object.kind === 'dict' || object.kind === 'stream' ? object.entries.get(key) : undefined
