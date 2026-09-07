import { getObject, type PdfDocument } from '../pdf/document.js'
import { dictEntry, type PdfObject } from '../pdf/object.js'

/**
 * PDF'teki imza sözlüklerini bulur.
 *
 * Bu modül hem YAZAN (DSS üretimi) hem OKUYAN (doğrulama) taraf tarafından
 * kullanılıyor. Kasten öyle: DSS'in `/VRI` anahtarı imzanın kimliğinden
 * türetiliyor ve iki taraf imzayı farklı buluyorsa, ürettiğimiz `/VRI`
 * kendi doğrulayıcımız dışında hiçbir yerde eşleşmez. Ortak bir bulucu
 * bunu yapısal olarak imkânsız kılıyor.
 */

/** Bulunmuş bir imza sözlüğü. */
export interface FoundSignature {
  readonly objectNumber: number
  readonly dictionary: PdfObject
  /** İmza alanının adı (`/T`), varsa. */
  readonly fieldName?: string
}

/**
 * Belgedeki imza sözlüklerini bulur.
 *
 * Çapraz başvurudaki her nesne taranıyor; `/AcroForm` üzerinden gitmek daha
 * zarif olurdu ama form eksik ya da bozuk olan belgelerde imzayı kaçırırdı.
 * Bir doğrulayıcının imzayı GÖRMEMESİ, geçersiz sayması kadar tehlikeli:
 * kullanıcı belgeyi imzasız sanır.
 *
 * @param document - Okunmuş belge
 * @returns İmza sözlükleri, nesne numarasına göre sıralı
 */
export const findSignatures = (document: PdfDocument): readonly FoundSignature[] => {
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

/**
 * İmza sözlüğünün türü belge zaman damgası mı.
 *
 * PAdES-LTA'nın damgası da bir imza alanıdır ve `/ByteRange` taşır; ayırt
 * eden `/Type /DocTimeStamp`. Karıştırılırsa damga "imzalayanı olmayan
 * bozuk imza" gibi görünür.
 */
export const isDocumentTimestamp = (dictionary: PdfObject): boolean => {
  const type = dictEntry(dictionary, 'Type')
  if (type?.kind === 'name' && type.value === 'DocTimeStamp') return true
  const subFilter = dictEntry(dictionary, 'SubFilter')
  return subFilter?.kind === 'name' && subFilter.value === 'ETSI.RFC3161'
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

/**
 * PDF metin dizesini çözer.
 *
 * Bayt sırası işaretiyle başlıyorsa UTF-16BE, değilse PDFDocEncoding —
 * ikincisi ASCII aralığında Latin-1 ile aynı. Türkçe karakterler içeren
 * değerler her zaman UTF-16BE yazılır.
 */
export const decodePdfText = (bytes: Uint8Array): string => {
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
