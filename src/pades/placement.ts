import { concat, toHex, utf8 } from '../core/bytes.js'
import { SigningError } from '../core/errors.js'
import { catalog, firstPage, readPdf, resolve, type PdfDocument } from '../pdf/document.js'
import {
  buildIncrementalUpdate,
  serializePdfObject,
  type PdfIndirectObject,
} from '../pdf/incremental.js'
import { dictEntry, indexOfSequence, type PdfObject } from '../pdf/object.js'

/**
 * İmza alanı yerleştirme — imza ile belge zaman damgasının ORTAK iskeleti.
 *
 * PAdES'te bir imza ve bir belge zaman damgası (`/DocTimeStamp`) PDF
 * açısından aynı şeydir: `/ByteRange` ve `/Contents` taşıyan bir imza
 * sözlüğü, ona bağlı görünmez bir widget, `/AcroForm`a eklenen bir alan.
 * Yalnızca sözlüğün birkaç girdisi ve `/Contents`e konan şey değişir.
 *
 * Bu iskelet ortak tutuluyor çünkü `/ByteRange` hesabı iki yerde ayrı ayrı
 * yazılırsa ikisi zamanla ayrışır — ve ayrıştığı gün, ürettiğimiz damga
 * kendi doğrulayıcımız dışında hiçbir yerde tutmaz.
 */

/** Varsayılan ayrılan yer: 16384 onaltılık karakter, yani 8 KB. */
export const DEFAULT_SIGNATURE_SPACE = 16384

/** {@link placeSignatureField} girdisi. */
export interface PlaceFieldInput {
  /** Üzerine yazılacak PDF. */
  readonly pdf: Uint8Array
  /** `/Contents` için ayrılacak onaltılık karakter sayısı. */
  readonly space: number
  /**
   * İmza sözlüğünün `/ByteRange` ve `/Contents` DIŞINDAKİ girdileri;
   * serileştirilmiş PDF metni olarak, sözlük ayraçları olmadan.
   */
  readonly dictionary: string
  /** `/T` alan adının öneki. */
  readonly fieldPrefix: string
}

/** Yerleştirilmiş ama içi hâlâ boş olan imza alanı. */
export interface PlacedField {
  /** `/Contents` sıfır dolu hâliyle birleştirilmiş dosya. */
  readonly assembled: Uint8Array
  /** `/ByteRange`ın gösterdiği baytlar — imzalanacak ya da damgalanacak olan. */
  readonly signedBytes: Uint8Array
  /**
   * DER'i `/Contents`e koyar ve dosyayı döndürür.
   *
   * @throws {SigningError} DER ayrılan yere sığmazsa
   */
  readonly finish: (der: Uint8Array) => Uint8Array
}

/**
 * İmza alanını artımlı güncellemeyle yerleştirir ve `/ByteRange`ı hesaplar.
 *
 * @param input - {@link PlaceFieldInput}
 * @returns İçi doldurulmayı bekleyen alan
 */
export const placeSignatureField = (input: PlaceFieldInput): PlacedField => {
  const { space } = input
  if (space < 1024 || space % 2 !== 0) {
    throw new SigningError('İmza için ayrılan yer en az 1024 ve çift sayıda olmalı.')
  }

  const document = readPdf(input.pdf)
  const root = catalog(document)
  const page = firstPage(document)

  const signatureNumber = document.size
  const annotationNumber = document.size + 1

  // `/ByteRange` ve `/Contents` SABİT genişlikte yer tutucularla yazılır:
  // gerçek değerler ancak yerleşim bittikten sonra bilinir ve genişlik
  // değişirse tüm konumlar kayar.
  const byteRangePlaceholder = `[${'0'.repeat(10)} ${'0'.repeat(10)} ${'0'.repeat(10)} ${'0'.repeat(10)}]`
  const signatureBody = concat(
    utf8('<< '),
    utf8(input.dictionary),
    utf8(`\n/ByteRange ${byteRangePlaceholder}\n`),
    utf8(`/Contents <${'0'.repeat(space)}>\n`),
    utf8('>>'),
  )

  // PAdES'te görünmez imza bile bir sayfaya bağlanmak zorunda; sıfır
  // boyutlu dikdörtgen "görünmez" demenin standart yolu.
  const annotationBody = utf8(
    '<< /Type /Annot /Subtype /Widget /FT /Sig /Ff 0 ' +
      '/Rect [0 0 0 0] /F 132 ' +
      `/T ${pdfText(`${input.fieldPrefix}-${String(signatureNumber)}`)} ` +
      `/V ${String(signatureNumber)} 0 R ` +
      `/P ${String(page.reference)} 0 R >>`,
  )

  const objects: PdfIndirectObject[] = [
    { number: signatureNumber, body: signatureBody },
    { number: annotationNumber, body: annotationBody },
    { number: page.reference, body: updatedPage(document, page.object, annotationNumber) },
  ]

  // AcroForm ayrı bir nesnede olabilir; öyleyse ona eklenir, değilse
  // kataloğa doğrudan yazılır. Var olan alanların üzerine yazmak, belgede
  // önceden bulunan form alanlarını yok etmek olurdu.
  const acroFormEntry = dictEntry(root.object, 'AcroForm')
  if (acroFormEntry?.kind === 'ref') {
    const existing = resolve(document, acroFormEntry)
    objects.push({
      number: acroFormEntry.number,
      body: updatedAcroForm(existing, annotationNumber),
    })
  } else {
    objects.push({
      number: root.reference,
      body: updatedCatalog(root.object, acroFormEntry, annotationNumber),
    })
  }

  // `/ID` varsa fragmanda korunur: bazı görüntüleyiciler eksikliğinde
  // belgeyi "değiştirilmiş" sayar.
  const documentId = document.trailer.get('ID')
  const assembled = buildIncrementalUpdate({
    original: input.pdf,
    previousStartXref: document.startXref,
    rootReference: root.reference,
    objects,
    size: document.size + 2,
    ...(documentId === undefined ? {} : { extraTrailer: new Map([['ID', documentId]]) }),
  })

  // ── /ByteRange hesabı ──────────────────────────────────────────────────
  const contentsMarker = utf8('/Contents <')
  const markerAt = indexOfSequence(assembled, contentsMarker, input.pdf.length)
  if (markerAt === -1) throw new SigningError('PDF: imza yer tutucusu bulunamadı.')
  const openAngle = markerAt + contentsMarker.length - 1
  const afterCloseAngle = openAngle + space + 2

  const byteRange = [0, openAngle, afterCloseAngle, assembled.length - afterCloseAngle]
  const patched = patchByteRange(assembled, byteRange, input.pdf.length)

  // İmzalanan baytlar: `/Contents <…>` dışındaki her şey.
  const signedBytes = concat(patched.subarray(0, byteRange[1]), patched.subarray(byteRange[2]))

  return {
    assembled: patched,
    signedBytes,
    finish: (der: Uint8Array): Uint8Array => {
      if (der.length * 2 > space) {
        throw new SigningError(
          `İmza ayrılan yere sığmıyor: ${String(der.length * 2)} > ${String(space)} onaltılık karakter. ` +
            'signatureSpace seçeneğini artırın.',
        )
      }
      // Yer tutucu zaten sıfırlarla dolu olduğu için `padEnd` çıktıyı
      // DEĞİŞTİRMİYOR — savunma amaçlı duruyor: yer tutucu ileride başka
      // bir karakterle doldurulursa imzadan artan bölge çöp kalmasın.
      const hex = utf8(toHex(der).padEnd(space, '0'))
      const out = new Uint8Array(patched)
      out.set(hex, openAngle + 1)
      return out
    },
  }
}

/** `/ByteRange` yer tutucusunu gerçek değerlerle doldurur. */
const patchByteRange = (
  assembled: Uint8Array,
  byteRange: readonly number[],
  from: number,
): Uint8Array => {
  const marker = utf8('/ByteRange [')
  const at = indexOfSequence(assembled, marker, from)
  if (at === -1) throw new SigningError('PDF: /ByteRange yer tutucusu bulunamadı.')

  // Yer tutucu genişliği sabit: dört alan, her biri 10 karakter, aralarında
  // birer boşluk. Gerçek değerler soldan yazılır, kalanı boşlukla dolar —
  // toplam genişlik değişmediği için hiçbir konum kaymaz.
  const start = at + marker.length
  const text = byteRange.map((value) => String(value).padEnd(10, ' ')).join(' ')
  const out = new Uint8Array(assembled)
  out.set(utf8(text), start)
  return out
}

/** Sayfaya imza alanını ekler. */
const updatedPage = (
  document: PdfDocument,
  page: PdfObject,
  annotationNumber: number,
): Uint8Array => {
  if (page.kind !== 'dict') throw new SigningError('PDF: sayfa sözlük değil.')
  const entries = new Map(page.entries)
  const existing = resolve(document, entries.get('Annots'))
  const annots: PdfObject[] = existing?.kind === 'array' ? [...existing.items] : []
  annots.push({ kind: 'ref', number: annotationNumber, generation: 0 })
  entries.set('Annots', { kind: 'array', items: annots })
  return serializePdfObject({ kind: 'dict', entries })
}

/** Kataloğa `/AcroForm` ekler ya da var olanı genişletir. */
const updatedCatalog = (
  root: PdfObject,
  acroForm: PdfObject | undefined,
  annotationNumber: number,
): Uint8Array => {
  if (root.kind !== 'dict') throw new SigningError('PDF: katalog sözlük değil.')
  const entries = new Map(root.entries)
  entries.set('AcroForm', {
    kind: 'dict',
    entries: acroFormEntries(acroForm, annotationNumber),
  })
  return serializePdfObject({ kind: 'dict', entries })
}

/** Ayrı nesnedeki `/AcroForm`u günceller. */
const updatedAcroForm = (existing: PdfObject | undefined, annotationNumber: number): Uint8Array =>
  serializePdfObject({ kind: 'dict', entries: acroFormEntries(existing, annotationNumber) })

/**
 * `/AcroForm` içeriğini kurar.
 *
 * `/SigFlags 3` = imza alanı var (1) ve belge artımlı güncelleme dışında
 * kaydedilmemeli (2). İkinci bit, görüntüleyicinin belgeyi yeniden yazıp
 * imzayı bozmasını engelliyor.
 */
const acroFormEntries = (
  existing: PdfObject | undefined,
  annotationNumber: number,
): Map<string, PdfObject> => {
  const entries =
    existing?.kind === 'dict' ? new Map(existing.entries) : new Map<string, PdfObject>()
  const fieldsEntry = entries.get('Fields')
  const fields: PdfObject[] = fieldsEntry?.kind === 'array' ? [...fieldsEntry.items] : []
  fields.push({ kind: 'ref', number: annotationNumber, generation: 0 })
  entries.set('Fields', { kind: 'array', items: fields })
  entries.set('SigFlags', { kind: 'number', value: 3 })
  return entries
}

/** PDF tarih dizesi — `(D:YYYYMMDDHHmmSSZ)`. */
export const pdfDate = (when: Date): string => {
  const pad = (value: number): string => String(value).padStart(2, '0')
  return (
    `(D:${String(when.getUTCFullYear())}${pad(when.getUTCMonth() + 1)}${pad(when.getUTCDate())}` +
    `${pad(when.getUTCHours())}${pad(when.getUTCMinutes())}${pad(when.getUTCSeconds())}Z)`
  )
}

/**
 * PDF metin dizesi.
 *
 * ASCII dışı karakterler için UTF-16BE ve bayt sırası işareti gerekiyor;
 * `İstanbul` gibi bir değeri Latin-1 yazmak görüntüleyicide bozuk çıkar.
 */
export const pdfText = (text: string): string => {
  const ascii = /^[\x20-\x7e]*$/.test(text)
  if (ascii) return `(${text.replace(/([()\\])/g, '\\$1')})`
  let hex = 'FEFF'
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0
    if (code > 0xffff) {
      const adjusted = code - 0x10000
      hex += (0xd800 + (adjusted >> 10)).toString(16).padStart(4, '0')
      hex += (0xdc00 + (adjusted & 0x3ff)).toString(16).padStart(4, '0')
    } else {
      hex += code.toString(16).padStart(4, '0')
    }
  }
  return `<${hex.toUpperCase()}>`
}
