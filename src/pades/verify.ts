import { decodeDerAt } from '../asn1/der.js'
import { cadesVerify, type CadesTimestampResult, type CadesWarning } from '../cades/verify.js'
import { concat } from '../core/bytes.js'
import { VerificationError } from '../core/errors.js'
import { getObject, readPdf, resolve, type PdfDocument } from '../pdf/document.js'
import { dictEntry, type PdfObject } from '../pdf/object.js'
import type { CertificateInfo } from '../pki/certificate.js'

/**
 * PAdES doğrulama.
 *
 * İmzanın kendisi ayrık bir CAdES imzasıdır ve doğrulaması
 * {@link ../cades/verify.js | CAdES katmanına} devredilir. Bu modülün
 * kendine ait tek işi PDF'e özgü olan soru: **imza belgenin ne kadarını
 * kapsıyor?**
 */

/** PDF'e özgü uyarılar. */
export interface PadesWarning {
  readonly code: 'partial-coverage' | 'byte-range-malformed'
  readonly message: string
}

/** Tek bir PDF imzasının doğrulama sonucu. */
export interface PadesSignatureResult {
  /** İmza alanının adı (`/T`), varsa. */
  readonly fieldName?: string
  /** İmzanın bulunduğu nesne numarası. */
  readonly objectNumber: number
  readonly valid: boolean
  /** Geçersizse nedeni. */
  readonly reason?: string
  readonly signer?: CertificateInfo
  readonly signingTime?: Date
  /** İmza gerekçesi (`/Reason`). */
  readonly reasonText?: string
  /** İmzanın atıldığı yer (`/Location`). */
  readonly location?: string
  /**
   * İmza belgenin TAMAMINI kapsıyor mu.
   *
   * `false` ise imzadan sonra belgeye bir şey eklenmiş demektir. Bu tek
   * başına bir saldırı değil — artımlı güncelleme PDF'in normal davranışı
   * ve ikinci bir imza da böyle eklenir — ama kapsam dışındaki içerik
   * imzalanmamıştır ve bunun bilinmesi gerekir.
   */
  readonly coversWholeDocument: boolean
  readonly timestamps: readonly CadesTimestampResult[]
  readonly warnings: readonly (CadesWarning | PadesWarning)[]
}

/** {@link padesVerify} sonucu. */
export interface PadesVerification {
  /** Belgedeki imzalar, dosyadaki sıralarına göre. */
  readonly signatures: readonly PadesSignatureResult[]
  /** Hepsi geçerli mi. */
  readonly valid: boolean
}

/**
 * PDF'teki imzaları doğrular.
 *
 * @param pdf - İmzalı PDF
 * @returns Her imza için bir sonuç
 * @throws {VerificationError} PDF okunamazsa ya da hiç imza yoksa
 *
 * @example
 * ```ts
 * const sonuc = padesVerify(readFileSync('imzali.pdf'))
 * for (const imza of sonuc.signatures) {
 *   console.log(imza.fieldName, imza.valid, imza.coversWholeDocument)
 * }
 * ```
 */
export const padesVerify = (pdf: Uint8Array): PadesVerification => {
  let document: PdfDocument
  try {
    document = readPdf(pdf)
  } catch (error) {
    throw new VerificationError(
      `PDF okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  const signatures = findSignatures(document)
  if (signatures.length === 0) throw new VerificationError("PDF'te imza alanı yok.")

  const results = signatures.map((entry) => verifySignature(document, entry))
  return { signatures: results, valid: results.every((result) => result.valid) }
}

/** Bulunmuş bir imza sözlüğü. */
interface FoundSignature {
  readonly objectNumber: number
  readonly dictionary: PdfObject
  readonly fieldName?: string
}

/**
 * Belgedeki imza sözlüklerini bulur.
 *
 * Çapraz başvurudaki her nesne taranıyor; `/AcroForm` üzerinden gitmek daha
 * zarif olurdu ama form eksik ya da bozuk olan belgelerde imzayı kaçırırdı.
 * Bir doğrulayıcının imzayı GÖRMEMESİ, geçersiz sayması kadar tehlikeli:
 * kullanıcı belgeyi imzasız sanır.
 */
const findSignatures = (document: PdfDocument): readonly FoundSignature[] => {
  const names = fieldNames(document)
  const found: FoundSignature[] = []
  for (const number of [...document.xref.keys()].sort((a, b) => a - b)) {
    let object: PdfObject | undefined
    try {
      object = getObject(document, number)
    } catch {
      continue
    }
    if (object?.kind !== 'dict') continue
    if (dictEntry(object, 'ByteRange') === undefined) continue
    if (dictEntry(object, 'Contents') === undefined) continue
    const name = names.get(number)
    found.push({
      objectNumber: number,
      dictionary: object,
      ...(name === undefined ? {} : { fieldName: name }),
    })
  }
  return found
}

/** İmza sözlüğü numarası → alan adı eşlemesi (`/AcroForm` üzerinden). */
const fieldNames = (document: PdfDocument): ReadonlyMap<number, string> => {
  const names = new Map<number, string>()
  for (const number of document.xref.keys()) {
    let object: PdfObject | undefined
    try {
      object = getObject(document, number)
    } catch {
      continue
    }
    if (object?.kind !== 'dict') continue
    const type = dictEntry(object, 'FT')
    if (type?.kind !== 'name' || type.value !== 'Sig') continue
    const value = dictEntry(object, 'V')
    const title = dictEntry(object, 'T')
    if (value?.kind === 'ref' && title?.kind === 'string') {
      names.set(value.number, decodePdfText(title.value))
    }
  }
  return names
}

/** Tek bir imzayı doğrular. */
const verifySignature = (document: PdfDocument, entry: FoundSignature): PadesSignatureResult => {
  const base = {
    objectNumber: entry.objectNumber,
    ...(entry.fieldName === undefined ? {} : { fieldName: entry.fieldName }),
  }

  const rangeEntry = resolve(document, dictEntry(entry.dictionary, 'ByteRange'))
  if (rangeEntry?.kind !== 'array' || rangeEntry.items.length < 4) {
    return {
      ...base,
      valid: false,
      reason: '/ByteRange dizisi eksik ya da bozuk.',
      coversWholeDocument: false,
      timestamps: [],
      warnings: [{ code: 'byte-range-malformed', message: '/ByteRange okunamadı.' }],
    }
  }
  const range = rangeEntry.items.map((item) => (item.kind === 'number' ? item.value : -1))
  if (range.some((value) => value < 0) || range.length % 2 !== 0) {
    return {
      ...base,
      valid: false,
      reason: '/ByteRange değerleri geçersiz.',
      coversWholeDocument: false,
      timestamps: [],
      warnings: [{ code: 'byte-range-malformed', message: '/ByteRange değerleri negatif.' }],
    }
  }

  const contents = resolve(document, dictEntry(entry.dictionary, 'Contents'))
  if (contents?.kind !== 'string') {
    return {
      ...base,
      valid: false,
      reason: '/Contents bir dize değil.',
      coversWholeDocument: false,
      timestamps: [],
      warnings: [],
    }
  }

  // `/Contents` sabit genişliktedir ve imzadan artan yer sıfırla doldurulur.
  // İlk DER değerini alıp kalanı atmak gerekiyor; doğrudan çözümlemek
  // "değerden sonra artık bayt var" hatası verirdi.
  let cms: Uint8Array
  try {
    cms = decodeDerAt(contents.value, 0).node.raw
  } catch (error) {
    return {
      ...base,
      valid: false,
      reason: `/Contents içindeki CMS okunamadı: ${error instanceof Error ? error.message : String(error)}`,
      coversWholeDocument: false,
      timestamps: [],
      warnings: [],
    }
  }

  // İmzalanan baytlar: `/ByteRange`ın gösterdiği dilimlerin birleşimi.
  const slices: Uint8Array[] = []
  for (let i = 0; i + 1 < range.length; i += 2) {
    const start = range[i] ?? 0
    const length = range[i + 1] ?? 0
    if (start + length > document.bytes.length) {
      return {
        ...base,
        valid: false,
        reason: '/ByteRange dosya sınırlarının dışını gösteriyor.',
        coversWholeDocument: false,
        timestamps: [],
        warnings: [{ code: 'byte-range-malformed', message: '/ByteRange dosyayı aşıyor.' }],
      }
    }
    slices.push(document.bytes.subarray(start, start + length))
  }
  const signedBytes = concat(...slices)

  const covered = coversWholeDocument(range, document.bytes.length)
  const outcome = cadesVerify(cms, { content: signedBytes })
  if (!outcome.valid) {
    return {
      ...base,
      valid: false,
      reason: outcome.reason,
      coversWholeDocument: covered,
      timestamps: [],
      warnings: [],
    }
  }

  const warnings: (CadesWarning | PadesWarning)[] = [...outcome.warnings]
  if (!covered) {
    warnings.push({
      code: 'partial-coverage',
      message:
        'İmza belgenin tamamını kapsamıyor — imzadan sonra içerik eklenmiş. ' +
        'Kapsam dışındaki bölüm imzalanmamıştır.',
    })
  }

  const reasonText = textEntry(document, entry.dictionary, 'Reason')
  const location = textEntry(document, entry.dictionary, 'Location')
  return {
    ...base,
    valid: true,
    signer: outcome.signer,
    ...(outcome.signingTime === undefined ? {} : { signingTime: outcome.signingTime }),
    ...(reasonText === undefined ? {} : { reasonText }),
    ...(location === undefined ? {} : { location }),
    coversWholeDocument: covered,
    timestamps: outcome.timestamps,
    warnings,
  }
}

/**
 * `/ByteRange` belgenin tamamını kapsıyor mu.
 *
 * Kapsama şu demek: dilimler dosyanın başından başlıyor, aralarında tek bir
 * boşluk var (imzanın kendisi) ve son dilim dosyanın sonuna kadar gidiyor.
 * Aksi hâlde imzalanmamış bir bölge kalır.
 */
const coversWholeDocument = (range: readonly number[], length: number): boolean => {
  if (range.length !== 4) return false
  const [firstStart, firstLength, secondStart, secondLength] = range as [
    number,
    number,
    number,
    number,
  ]
  if (firstStart !== 0) return false
  if (secondStart < firstStart + firstLength) return false
  return secondStart + secondLength === length
}

/** Sözlükten metin değeri okur. */
const textEntry = (
  document: PdfDocument,
  dictionary: PdfObject,
  key: string,
): string | undefined => {
  const value = resolve(document, dictEntry(dictionary, key))
  return value?.kind === 'string' ? decodePdfText(value.value) : undefined
}

/**
 * PDF metin dizesini çözer.
 *
 * Bayt sırası işaretiyle başlıyorsa UTF-16BE, değilse PDFDocEncoding —
 * ikincisi ASCII aralığında Latin-1 ile aynı. Türkçe karakterler içeren
 * değerler her zaman UTF-16BE yazılır.
 */
const decodePdfText = (bytes: Uint8Array): string => {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let out = ''
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode(((bytes[i] ?? 0) << 8) | (bytes[i + 1] ?? 0))
    }
    return out
  }
  let out = ''
  for (const byte of bytes) out += String.fromCharCode(byte)
  return out
}
