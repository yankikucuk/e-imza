import { inflateSync } from 'node:zlib'

import { fromUtf8, utf8 } from '../core/bytes.js'

import { dictEntry, lastIndexOfSequence, PdfReader, type PdfObject } from './object.js'

/**
 * PDF belge yapısını okur: çapraz başvuru, fragman ve nesne çözümleme.
 *
 * İmza eklemek için gereken kadarı. İçerik akışları açılmaz; yalnızca
 * çapraz başvuru akışları ve nesne akışları (`ObjStm`) çözülür, çünkü
 * belge kökü onların içinde olabilir.
 */

/** Bir nesnenin dosyadaki yeri. */
type XrefEntry =
  | { readonly kind: 'offset'; readonly offset: number }
  | { readonly kind: 'in-stream'; readonly stream: number; readonly index: number }

/** Okunmuş PDF belgesi. */
export interface PdfDocument {
  /** Özgün baytlar — hiçbir zaman değiştirilmez. */
  readonly bytes: Uint8Array
  /** Fragman sözlüğü (birden çok fragman birleştirilmiş hâliyle). */
  readonly trailer: ReadonlyMap<string, PdfObject>
  /** Nesne numarası → konum. */
  readonly xref: ReadonlyMap<number, XrefEntry>
  /** Son çapraz başvuru tablosunun dosyadaki konumu. */
  readonly startXref: number
  /** Belgedeki en büyük nesne numarası + 1. */
  readonly size: number
}

/**
 * PDF'i okur.
 *
 * @param bytes - Dosya içeriği
 * @returns Çözümlenmiş belge yapısı
 * @throws {SyntaxError} Dosya PDF değilse, şifreliyse ya da yapı bozuksa
 */
export const readPdf = (bytes: Uint8Array): PdfDocument => {
  if (fromUtf8(bytes.subarray(0, 5)) !== '%PDF-') {
    throw new SyntaxError('PDF: dosya %PDF- ile başlamıyor.')
  }

  const marker = lastIndexOfSequence(bytes, utf8('startxref'))
  if (marker === -1) throw new SyntaxError('PDF: startxref bulunamadı.')
  const reader = new PdfReader(bytes, marker + 'startxref'.length)
  const startXref = Number.parseInt(reader.readToken(), 10)
  if (!Number.isFinite(startXref)) throw new SyntaxError('PDF: startxref değeri okunamadı.')

  const xref = new Map<number, XrefEntry>()
  const trailer = new Map<string, PdfObject>()
  const visited = new Set<number>()
  let offset: number | undefined = startXref

  // Fragman zinciri: her bölüm bir öncekini `/Prev` ile gösterir. ÖNCE
  // okunan kazanır — en yeni tablo en sonda, dolayısıyla ilk okunan odur.
  while (offset !== undefined && !visited.has(offset)) {
    visited.add(offset)
    const section = readXrefSection(bytes, offset)
    for (const [number, entry] of section.entries) {
      if (!xref.has(number)) xref.set(number, entry)
    }
    for (const [key, value] of section.trailer) {
      if (!trailer.has(key)) trailer.set(key, value)
    }
    // Melez dosyalarda klasik tablonun yanında bir de akış bulunur.
    const hybrid = section.trailer.get('XRefStm')
    if (hybrid?.kind === 'number' && !visited.has(hybrid.value)) {
      visited.add(hybrid.value)
      const extra = readXrefSection(bytes, hybrid.value)
      for (const [number, entry] of extra.entries) {
        if (!xref.has(number)) xref.set(number, entry)
      }
    }
    const previous = section.trailer.get('Prev')
    offset = previous?.kind === 'number' ? previous.value : undefined
  }

  if (trailer.has('Encrypt')) {
    throw new SyntaxError(
      'PDF şifreli. İmza eklemek belgeyi çözmeyi gerektirir; bu kütüphane şifreli PDF açmaz.',
    )
  }

  const sizeEntry = trailer.get('Size')
  const size = sizeEntry?.kind === 'number' ? sizeEntry.value : maxObjectNumber(xref) + 1
  return { bytes, trailer, xref, startXref, size }
}

/** En büyük nesne numarası. */
const maxObjectNumber = (xref: ReadonlyMap<number, XrefEntry>): number => {
  let max = 0
  for (const number of xref.keys()) if (number > max) max = number
  return max
}

/** Tek bir çapraz başvuru bölümü. */
interface XrefSection {
  readonly entries: ReadonlyMap<number, XrefEntry>
  readonly trailer: ReadonlyMap<string, PdfObject>
}

/** Klasik tabloyu ya da çapraz başvuru akışını okur. */
const readXrefSection = (bytes: Uint8Array, offset: number): XrefSection => {
  const reader = new PdfReader(bytes, offset)
  reader.skipWhitespace()
  if (reader.consume('xref')) return readXrefTable(reader)

  // Çapraz başvuru akışı: `N G obj << … >> stream`.
  reader.offset = offset
  reader.readToken()
  reader.readToken()
  if (!reader.consume('obj')) {
    throw new SyntaxError(`PDF: konum ${String(offset)} çapraz başvuru içermiyor.`)
  }
  const object = reader.readObject()
  if (object.kind !== 'stream') throw new SyntaxError('PDF: çapraz başvuru akışı bekleniyordu.')
  return readXrefStream(object)
}

/** Klasik `xref` tablosu. */
const readXrefTable = (reader: PdfReader): XrefSection => {
  const entries = new Map<number, XrefEntry>()
  for (;;) {
    reader.skipWhitespace()
    const save = reader.offset
    const token = reader.readToken()
    if (token === 'trailer') break
    if (!/^\d+$/.test(token)) {
      reader.offset = save
      break
    }
    const start = Number.parseInt(token, 10)
    const count = Number.parseInt(reader.readToken(), 10)
    for (let i = 0; i < count; i += 1) {
      const position = Number.parseInt(reader.readToken(), 10)
      reader.readToken() // üretim numarası
      const type = reader.readToken()
      // `f` serbest girdi: nesne yok.
      if (type === 'n') entries.set(start + i, { kind: 'offset', offset: position })
    }
  }
  const trailerObject = reader.readObject()
  const trailer =
    trailerObject.kind === 'dict' ? trailerObject.entries : new Map<string, PdfObject>()
  return { entries, trailer }
}

/** PDF 1.5+ çapraz başvuru akışı. */
const readXrefStream = (stream: PdfObject): XrefSection => {
  if (stream.kind !== 'stream') throw new SyntaxError('PDF: akış bekleniyordu.')
  const data = decodeStream(stream)

  const widthsEntry = stream.entries.get('W')
  if (widthsEntry?.kind !== 'array') throw new SyntaxError('PDF: /W alanı yok.')
  const widths = widthsEntry.items.map((item) => (item.kind === 'number' ? item.value : 0))

  const sizeEntry = stream.entries.get('Size')
  const size = sizeEntry?.kind === 'number' ? sizeEntry.value : 0
  const indexEntry = stream.entries.get('Index')
  const index =
    indexEntry?.kind === 'array'
      ? indexEntry.items.map((item) => (item.kind === 'number' ? item.value : 0))
      : [0, size]

  const rowWidth = widths.reduce((total, width) => total + width, 0)
  const entries = new Map<number, XrefEntry>()
  let cursor = 0

  for (let pair = 0; pair + 1 < index.length; pair += 2) {
    const first = index[pair] ?? 0
    const count = index[pair + 1] ?? 0
    for (let i = 0; i < count && cursor + rowWidth <= data.length; i += 1) {
      const fields: number[] = []
      for (const width of widths) {
        let value = 0
        for (let b = 0; b < width; b += 1) {
          value = value * 256 + (data[cursor] ?? 0)
          cursor += 1
        }
        fields.push(value)
      }
      // `/W`nin ilk alanı 0 ise tür varsayılan olarak 1'dir.
      const type = widths[0] === 0 ? 1 : (fields[0] ?? 0)
      const number = first + i
      if (entries.has(number)) continue
      if (type === 1) entries.set(number, { kind: 'offset', offset: fields[1] ?? 0 })
      else if (type === 2) {
        entries.set(number, {
          kind: 'in-stream',
          stream: fields[1] ?? 0,
          index: fields[2] ?? 0,
        })
      }
    }
  }
  return { entries, trailer: stream.entries }
}

/**
 * Akış verisini süzgeçten geçirir.
 *
 * Yalnızca `FlateDecode` destekleniyor; çapraz başvuru ve nesne akışları
 * pratikte hep onu kullanır. Başka bir süzgeç görülürse **açıkça
 * reddedilir** — sessizce ham baytları döndürmek, çöp veriyi yapı sanmak
 * olurdu.
 */
const decodeStream = (stream: PdfObject): Uint8Array => {
  if (stream.kind !== 'stream') throw new SyntaxError('PDF: akış bekleniyordu.')
  const filter = stream.entries.get('Filter')
  const names =
    filter === undefined
      ? []
      : filter.kind === 'name'
        ? [filter.value]
        : filter.kind === 'array'
          ? filter.items.flatMap((item) => (item.kind === 'name' ? [item.value] : []))
          : []

  let data = stream.raw
  for (const name of names) {
    if (name !== 'FlateDecode') {
      throw new SyntaxError(`PDF: desteklenmeyen akış süzgeci: ${name}`)
    }
    data = new Uint8Array(inflateSync(Buffer.from(data)))
  }

  // `/DecodeParms` ile öngörücü (predictor) uygulanmış olabilir.
  const parms = stream.entries.get('DecodeParms')
  const parmsDict =
    parms?.kind === 'dict'
      ? parms
      : parms?.kind === 'array'
        ? parms.items.find((item) => item.kind === 'dict')
        : undefined
  if (parmsDict !== undefined) {
    const predictor = dictEntry(parmsDict, 'Predictor')
    if (predictor?.kind === 'number' && predictor.value >= 10) {
      const columnsEntry = dictEntry(parmsDict, 'Columns')
      const columns = columnsEntry?.kind === 'number' ? columnsEntry.value : 1
      data = undoPngPredictor(data, columns)
    }
  }
  return data
}

/**
 * PNG öngörücüsünü geri alır.
 *
 * Çapraz başvuru akışları neredeyse her zaman `Predictor 12` (PNG Up)
 * kullanır. Geri almadan satırlar anlamsız çıkar ve tablo sessizce yanlış
 * okunur — bu yüzden desteklenmesi zorunlu.
 */
const undoPngPredictor = (data: Uint8Array, columns: number): Uint8Array => {
  const rowSize = columns + 1
  const rows = Math.floor(data.length / rowSize)
  const out = new Uint8Array(rows * columns)
  let previous = new Uint8Array(columns)
  for (let row = 0; row < rows; row += 1) {
    const type = data[row * rowSize] ?? 0
    const current = new Uint8Array(columns)
    for (let i = 0; i < columns; i += 1) {
      const raw = data[row * rowSize + 1 + i] ?? 0
      const up = previous[i] ?? 0
      const left = i >= 1 ? (current[i - 1] ?? 0) : 0
      // Yalnızca sahada görülen üç tür; diğerleri için ham değer.
      current[i] =
        type === 2
          ? (raw + up) & 0xff
          : type === 1
            ? (raw + left) & 0xff
            : type === 0
              ? raw
              : (raw + up) & 0xff
    }
    out.set(current, row * columns)
    previous = current
  }
  return out
}

/**
 * Bir nesneyi numarasıyla çözer.
 *
 * @param document - Okunmuş belge
 * @param number - Nesne numarası
 * @returns Nesne; bulunamazsa `undefined`
 */
export const getObject = (document: PdfDocument, number: number): PdfObject | undefined => {
  const entry = document.xref.get(number)
  if (entry === undefined) return undefined

  if (entry.kind === 'offset') {
    const reader = new PdfReader(document.bytes, entry.offset)
    reader.readToken() // nesne numarası
    reader.readToken() // üretim numarası
    if (!reader.consume('obj')) return undefined
    return reader.readObject()
  }

  // Nesne akışının içinde.
  const container = getObject(document, entry.stream)
  if (container?.kind !== 'stream') return undefined
  const data = decodeStream(container)
  const countEntry = container.entries.get('N')
  const firstEntry = container.entries.get('First')
  if (countEntry?.kind !== 'number' || firstEntry?.kind !== 'number') return undefined

  const header = new PdfReader(data, 0)
  for (let i = 0; i < countEntry.value; i += 1) {
    header.readToken() // nesne numarası
    const offset = Number.parseInt(header.readToken(), 10)
    if (i === entry.index) {
      return new PdfReader(data, firstEntry.value + offset).readObject()
    }
  }
  return undefined
}

/**
 * Dolaylı başvuruyu çözer; nesne zaten doğrudansa olduğu gibi döner.
 *
 * @param document - Okunmuş belge
 * @param object - Çözülecek nesne
 * @returns Çözülmüş nesne
 */
export const resolve = (
  document: PdfDocument,
  object: PdfObject | undefined,
): PdfObject | undefined => (object?.kind === 'ref' ? getObject(document, object.number) : object)

/**
 * Belge kökünü (`/Root`) verir.
 *
 * @param document - Okunmuş belge
 * @returns Katalog sözlüğü
 * @throws {SyntaxError} Katalog bulunamazsa
 */
export const catalog = (
  document: PdfDocument,
): { readonly reference: number; readonly object: PdfObject } => {
  const root = document.trailer.get('Root')
  if (root?.kind !== 'ref') throw new SyntaxError('PDF: /Root dolaylı başvuru değil.')
  const object = getObject(document, root.number)
  if (object === undefined) throw new SyntaxError('PDF: katalog çözülemedi.')
  return { reference: root.number, object }
}

/**
 * İlk sayfayı verir.
 *
 * İmzanın görsel alanı (widget) bir sayfaya bağlanmak zorunda; PAdES'te
 * görünmez imza bile bir sayfa nesnesine iliştirilir.
 *
 * @param document - Okunmuş belge
 * @returns Sayfa nesne numarası ve sözlüğü
 * @throws {SyntaxError} Sayfa ağacı okunamazsa
 */
export const firstPage = (
  document: PdfDocument,
): { readonly reference: number; readonly object: PdfObject } => {
  const pagesEntry = dictEntry(catalog(document).object, 'Pages')
  if (pagesEntry?.kind !== 'ref') throw new SyntaxError('PDF: /Pages bulunamadı.')

  const descend = (reference: number, depth: number): number | undefined => {
    if (depth > 64) return undefined
    const node = getObject(document, reference)
    if (node === undefined) return undefined
    const type = dictEntry(node, 'Type')
    if (type?.kind === 'name' && type.value === 'Page') return reference
    const kids = dictEntry(node, 'Kids')
    if (kids?.kind !== 'array') return undefined
    for (const kid of kids.items) {
      if (kid.kind !== 'ref') continue
      const found = descend(kid.number, depth + 1)
      if (found !== undefined) return found
    }
    return undefined
  }

  const reference = descend(pagesEntry.number, 0)
  if (reference === undefined) throw new SyntaxError('PDF: sayfa bulunamadı.')
  const object = getObject(document, reference)
  if (object === undefined) throw new SyntaxError('PDF: sayfa çözülemedi.')
  return { reference, object }
}
