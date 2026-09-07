import { concat, utf8 } from '../core/bytes.js'

import type { PdfObject } from './object.js'

/**
 * PDF artımlı güncelleme yazıcısı.
 *
 * PAdES'in temel kuralı: **özgün baytlara dokunulmaz.** İmza, dosyanın
 * sonuna eklenen yeni bir bölümle gelir; eski çapraz başvuru tablosu
 * `/Prev` ile zincire bağlanır. Böylece imzadan önceki belge bayt bayt
 * korunur ve daha önce atılmış imzalar bozulmaz.
 *
 * Bu, XAdES'teki `UnsignedProperties` mantığının PDF karşılığı: değişiklik
 * eklenir, var olan değiştirilmez.
 */

/** Yazılacak bir dolaylı nesne. */
export interface PdfIndirectObject {
  readonly number: number
  readonly generation?: number
  /** Nesnenin serileştirilmiş gövdesi. */
  readonly body: Uint8Array
}

/** PDF nesnesini metne çevirir. */
export const serializePdfObject = (object: PdfObject): Uint8Array => {
  switch (object.kind) {
    case 'null':
      return utf8('null')
    case 'boolean':
      return utf8(object.value ? 'true' : 'false')
    case 'number':
      return utf8(formatNumber(object.value))
    case 'name':
      return utf8(`/${escapeName(object.value)}`)
    case 'ref':
      return utf8(`${String(object.number)} ${String(object.generation)} R`)
    case 'string':
      return object.hex ? serializeHexString(object.value) : serializeLiteralString(object.value)
    case 'array':
      return concat(
        utf8('['),
        ...object.items.flatMap((item, index) =>
          index === 0 ? [serializePdfObject(item)] : [utf8(' '), serializePdfObject(item)],
        ),
        utf8(']'),
      )
    case 'dict':
      return serializeDictionary(object.entries)
    case 'stream':
      return concat(
        serializeDictionary(object.entries),
        utf8('\nstream\n'),
        object.raw,
        utf8('\nendstream'),
      )
  }
}

/** Sözlüğü yazar. */
const serializeDictionary = (entries: ReadonlyMap<string, PdfObject>): Uint8Array => {
  const parts: Uint8Array[] = [utf8('<<')]
  for (const [key, value] of entries) {
    parts.push(utf8(`/${escapeName(key)} `), serializePdfObject(value), utf8(' '))
  }
  parts.push(utf8('>>'))
  return concat(...parts)
}

/**
 * PDF sayısını yazar.
 *
 * Üstel gösterim PDF'te geçersizdir; çok küçük ya da çok büyük sayılar
 * ondalık olarak yazılmalı.
 */
const formatNumber = (value: number): string => {
  if (Number.isInteger(value)) return String(value)
  return value.toFixed(6).replace(/0+$/, '').replace(/\.$/, '')
}

/** Ad içindeki özel karakterleri `#XX` ile kaçırır. */
const escapeName = (name: string): string => {
  let out = ''
  for (const char of name) {
    const code = char.charCodeAt(0)
    if (code < 0x21 || code > 0x7e || '()<>[]{}/%#'.includes(char)) {
      out += `#${code.toString(16).padStart(2, '0')}`
    } else {
      out += char
    }
  }
  return out
}

/** `(metin)` biçiminde yazar. */
const serializeLiteralString = (value: Uint8Array): Uint8Array => {
  const out: number[] = [0x28]
  for (const byte of value) {
    // Parantez ve ters eğik çizgi kaçırılmak ZORUNDA; kaçırılmazsa dize
    // erken kapanır ve dosya bozulur.
    if (byte === 0x28 || byte === 0x29 || byte === 0x5c) out.push(0x5c)
    out.push(byte)
  }
  out.push(0x29)
  return new Uint8Array(out)
}

/** `<onaltılık>` biçiminde yazar. */
const serializeHexString = (value: Uint8Array): Uint8Array => {
  let hex = ''
  for (const byte of value) hex += byte.toString(16).padStart(2, '0')
  return utf8(`<${hex}>`)
}

/** {@link buildIncrementalUpdate} girdisi. */
export interface IncrementalUpdateInput {
  /** Özgün dosya. */
  readonly original: Uint8Array
  /** Önceki çapraz başvurunun konumu. */
  readonly previousStartXref: number
  /** Fragmanda taşınacak `/Root` başvurusu. */
  readonly rootReference: number
  /** Yeni ya da güncellenen nesneler. */
  readonly objects: readonly PdfIndirectObject[]
  /** Belgedeki en büyük nesne numarası + 1. */
  readonly size: number
  /** Fragmana eklenecek diğer girdiler (`/ID` gibi). */
  readonly extraTrailer?: ReadonlyMap<string, PdfObject>
}

/**
 * Artımlı güncelleme üretir ve özgün dosyanın sonuna ekler.
 *
 * @param input - {@link IncrementalUpdateInput}
 * @returns Güncellenmiş dosyanın tamamı
 */
export const buildIncrementalUpdate = (input: IncrementalUpdateInput): Uint8Array => {
  const parts: Uint8Array[] = [input.original]
  let offset = input.original.length

  // Özgün dosya satır sonuyla bitmiyorsa ekle: yeni bölüm kendi satırında
  // başlamalı, yoksa son simge ile ilk nesne numarası birleşir.
  const last = input.original[input.original.length - 1] ?? 0
  if (last !== 0x0a && last !== 0x0d) {
    parts.push(utf8('\n'))
    offset += 1
  }

  const positions = new Map<number, number>()
  const sorted = [...input.objects].sort((a, b) => a.number - b.number)
  for (const object of sorted) {
    positions.set(object.number, offset)
    const header = utf8(`${String(object.number)} ${String(object.generation ?? 0)} obj\n`)
    const footer = utf8('\nendobj\n')
    parts.push(header, object.body, footer)
    offset += header.length + object.body.length + footer.length
  }

  const xrefOffset = offset
  parts.push(utf8(buildXrefTable(positions)))

  const trailer = new Map<string, PdfObject>(input.extraTrailer ?? [])
  trailer.set('Size', { kind: 'number', value: input.size })
  trailer.set('Root', { kind: 'ref', number: input.rootReference, generation: 0 })
  trailer.set('Prev', { kind: 'number', value: input.previousStartXref })

  parts.push(
    utf8('trailer\n'),
    serializeDictionary(trailer),
    utf8(`\nstartxref\n${String(xrefOffset)}\n%%EOF\n`),
  )
  return concat(...parts)
}

/**
 * Klasik `xref` tablosunu yazar.
 *
 * Girdiler bitişik nesne numaralarına göre alt bölümlere ayrılır; PDF
 * biçimi bunu şart koşar ve tek bir blokta yazmak, aradaki numaralar
 * güncellenmemiş olsa bile onları güncellenmiş gösterirdi.
 */
const buildXrefTable = (positions: ReadonlyMap<number, number>): string => {
  const numbers = [...positions.keys()].sort((a, b) => a - b)
  const groups: { start: number; offsets: number[] }[] = []
  for (const number of numbers) {
    const current = groups[groups.length - 1]
    if (current !== undefined && number === current.start + current.offsets.length) {
      current.offsets.push(positions.get(number) ?? 0)
    } else {
      groups.push({ start: number, offsets: [positions.get(number) ?? 0] })
    }
  }

  let out = 'xref\n'
  for (const group of groups) {
    out += `${String(group.start)} ${String(group.offsets.length)}\n`
    for (const position of group.offsets) {
      // Her girdi TAM 20 bayt: 10 basamak, boşluk, 5 basamak, boşluk, tür,
      // iki karakterlik satır sonu. Sabit genişlik biçimin şartı.
      out += `${String(position).padStart(10, '0')} 00000 n \n`
    }
  }
  return out
}
