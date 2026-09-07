import { decodeDerAt } from '../asn1/der.js'
import { cadesVerify, type CadesTimestampResult, type CadesWarning } from '../cades/verify.js'
import { concat } from '../core/bytes.js'
import { VerificationError } from '../core/errors.js'
import { catalog, readPdf, resolve, type PdfDocument } from '../pdf/document.js'
import { dictEntry, type PdfObject } from '../pdf/object.js'
import type { CertificateInfo } from '../pki/certificate.js'
import { verifyTimestampToken } from '../pki/tsp.js'

import { readDss, vriKey, type DocumentSecurityStore } from './dss.js'
import {
  decodePdfText,
  findSignatures,
  isDocumentTimestamp,
  type FoundSignature,
} from './locate.js'

/**
 * PAdES doğrulama.
 *
 * İmzanın kendisi ayrık bir CAdES imzasıdır ve doğrulaması
 * {@link ../cades/verify.js | CAdES katmanına} devredilir. Bu modülün
 * kendine ait olan işleri PDF'e özgü olanlar: **imza belgenin ne kadarını
 * kapsıyor**, belgede DSS var mı, ve `/DocTimeStamp` damgaları tutuyor mu.
 */

/** PDF'e özgü uyarılar. */
export interface PadesWarning {
  readonly code:
    'partial-coverage' | 'byte-range-malformed' | 'document-timestamp-invalid' | 'vri-missing'
  readonly message: string
}

/**
 * PAdES uygunluk seviyesi (ETSI EN 319 142-1).
 *
 * Seviye yalnızca **doğrulanan** kanıtla yükselir: gömülü ama tutmayan bir
 * zaman damgası seviyeyi yükseltmez. Aksi hâlde "B-LTA" etiketi, kimsenin
 * denetlemediği bir iddiadan ibaret olurdu.
 */
export type PadesLevel = 'B-B' | 'B-T' | 'B-LT' | 'B-LTA'

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
   * başına bir saldırı değil — artımlı güncelleme PDF'in normal davranışı,
   * ikinci bir imza, DSS ve belge damgası da böyle eklenir — ama kapsam
   * dışındaki içerik imzalanmamıştır ve bunun bilinmesi gerekir.
   */
  readonly coversWholeDocument: boolean
  /** Doğrulanmış kanıta göre ulaşılan seviye. */
  readonly level: PadesLevel
  /** `/VRI` sözlüğünde bu imzanın anahtarı var mı. */
  readonly hasVri: boolean
  readonly timestamps: readonly CadesTimestampResult[]
  readonly warnings: readonly (CadesWarning | PadesWarning)[]
}

/** Belge zaman damgası (`/DocTimeStamp`) sonucu. */
export interface PadesDocumentTimestampResult {
  readonly objectNumber: number
  readonly fieldName?: string
  readonly valid: boolean
  readonly reason?: string
  /** TSA'nın bildirdiği zaman. */
  readonly genTime?: Date
  readonly policyOid?: string
  /** Damga belgenin tamamını kapsıyor mu. */
  readonly coversWholeDocument: boolean
}

/** {@link padesVerify} sonucu. */
export interface PadesVerification {
  /** Belgedeki imzalar, dosyadaki sıralarına göre. */
  readonly signatures: readonly PadesSignatureResult[]
  /** Belge zaman damgaları, dosyadaki sıralarına göre. */
  readonly documentTimestamps: readonly PadesDocumentTimestampResult[]
  /** Belgedeki doğrulama malzemesi; `/DSS` yoksa `undefined`. */
  readonly dss?: DocumentSecurityStore
  /** Hepsi geçerli mi — damgalar dahil. */
  readonly valid: boolean
}

/**
 * PDF'teki imzaları ve belge zaman damgalarını doğrular.
 *
 * @param pdf - İmzalı PDF
 * @returns Her imza ve her damga için bir sonuç
 * @throws {VerificationError} PDF okunamazsa ya da hiç imza alanı yoksa
 *
 * @example
 * ```ts
 * const sonuc = padesVerify(readFileSync('imzali.pdf'))
 * for (const imza of sonuc.signatures) {
 *   console.log(imza.fieldName, imza.valid, imza.level, imza.coversWholeDocument)
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

  const found = findSignatures(document)
  if (found.length === 0) throw new VerificationError("PDF'te imza alanı yok.")

  const dss = readDss(document, catalog(document).object)

  // Damgalar önce doğrulanır: imzaların seviyesi onların sonucuna bağlı.
  const stamps: { result: PadesDocumentTimestampResult; contentsAt: number }[] = []
  const signatureEntries: FoundSignature[] = []
  for (const entry of found) {
    if (isDocumentTimestamp(entry.dictionary)) {
      stamps.push(verifyDocumentTimestamp(document, entry))
    } else {
      signatureEntries.push(entry)
    }
  }

  const signatures = signatureEntries.map((entry) => verifySignature(document, entry, dss, stamps))
  const documentTimestamps = stamps.map((stamp) => stamp.result)

  return {
    signatures,
    documentTimestamps,
    ...(dss === undefined ? {} : { dss }),
    valid:
      signatures.every((result) => result.valid) &&
      documentTimestamps.every((result) => result.valid),
  }
}

/** `/ByteRange` ve `/Contents` okunmuş hâli. */
interface SignedRegion {
  readonly range: readonly number[]
  readonly contents: Uint8Array
  readonly signedBytes: Uint8Array
  readonly coversWholeDocument: boolean
}

/**
 * `/ByteRange` ve `/Contents`i çözer.
 *
 * @returns Bölge, ya da okunamadıysa nedeni
 */
const readSignedRegion = (
  document: PdfDocument,
  dictionary: PdfObject,
): SignedRegion | { readonly error: string; readonly code: PadesWarning['code'] } => {
  const rangeEntry = resolve(document, dictEntry(dictionary, 'ByteRange'))
  if (rangeEntry?.kind !== 'array' || rangeEntry.items.length < 4) {
    return { error: '/ByteRange dizisi eksik ya da bozuk.', code: 'byte-range-malformed' }
  }
  const range = rangeEntry.items.map((item) => (item.kind === 'number' ? item.value : -1))
  if (range.some((value) => value < 0) || range.length % 2 !== 0) {
    return { error: '/ByteRange değerleri geçersiz.', code: 'byte-range-malformed' }
  }

  const contents = resolve(document, dictEntry(dictionary, 'Contents'))
  if (contents?.kind !== 'string') {
    return { error: '/Contents bir dize değil.', code: 'byte-range-malformed' }
  }

  const slices: Uint8Array[] = []
  for (let i = 0; i + 1 < range.length; i += 2) {
    const start = range[i] ?? 0
    const length = range[i + 1] ?? 0
    if (start + length > document.bytes.length) {
      return {
        error: '/ByteRange dosya sınırlarının dışını gösteriyor.',
        code: 'byte-range-malformed',
      }
    }
    slices.push(document.bytes.subarray(start, start + length))
  }

  return {
    range,
    contents: contents.value,
    signedBytes: concat(...slices),
    coversWholeDocument: coversWholeDocument(range, document.bytes.length),
  }
}

/** Belge zaman damgasını doğrular. */
const verifyDocumentTimestamp = (
  document: PdfDocument,
  entry: FoundSignature,
): { result: PadesDocumentTimestampResult; contentsAt: number } => {
  const base = {
    objectNumber: entry.objectNumber,
    ...(entry.fieldName === undefined ? {} : { fieldName: entry.fieldName }),
  }

  const region = readSignedRegion(document, entry.dictionary)
  if ('error' in region) {
    return {
      result: { ...base, valid: false, reason: region.error, coversWholeDocument: false },
      contentsAt: -1,
    }
  }

  // `/Contents` sabit genişliktedir ve jetondan artan yer sıfırla doldurulur.
  let token: Uint8Array
  try {
    token = decodeDerAt(region.contents, 0).node.raw
  } catch (error) {
    return {
      result: {
        ...base,
        valid: false,
        reason: `Jeton okunamadı: ${error instanceof Error ? error.message : String(error)}`,
        coversWholeDocument: region.coversWholeDocument,
      },
      contentsAt: region.range[1] ?? -1,
    }
  }

  const outcome = verifyTimestampToken(token, { data: region.signedBytes })
  if (!outcome.valid) {
    return {
      result: {
        ...base,
        valid: false,
        reason: outcome.reason,
        coversWholeDocument: region.coversWholeDocument,
      },
      contentsAt: region.range[1] ?? -1,
    }
  }

  return {
    result: {
      ...base,
      valid: true,
      genTime: outcome.info.genTime,
      policyOid: outcome.info.policyOid,
      coversWholeDocument: region.coversWholeDocument,
    },
    contentsAt: region.range[1] ?? -1,
  }
}

/** Tek bir imzayı doğrular. */
const verifySignature = (
  document: PdfDocument,
  entry: FoundSignature,
  dss: DocumentSecurityStore | undefined,
  stamps: readonly { readonly result: PadesDocumentTimestampResult; readonly contentsAt: number }[],
): PadesSignatureResult => {
  const base = {
    objectNumber: entry.objectNumber,
    ...(entry.fieldName === undefined ? {} : { fieldName: entry.fieldName }),
  }
  const failed = (
    reason: string,
    covered: boolean,
    warnings: readonly (CadesWarning | PadesWarning)[] = [],
  ): PadesSignatureResult => ({
    ...base,
    valid: false,
    reason,
    coversWholeDocument: covered,
    level: 'B-B',
    hasVri: false,
    timestamps: [],
    warnings,
  })

  const region = readSignedRegion(document, entry.dictionary)
  if ('error' in region) {
    return failed(region.error, false, [{ code: region.code, message: region.error }])
  }

  // `/Contents` sabit genişliktedir ve imzadan artan yer sıfırla doldurulur.
  // İlk DER değerini alıp kalanı atmak gerekiyor; doğrudan çözümlemek
  // "değerden sonra artık bayt var" hatası verirdi.
  let cms: Uint8Array
  try {
    cms = decodeDerAt(region.contents, 0).node.raw
  } catch (error) {
    return failed(
      `/Contents içindeki CMS okunamadı: ${error instanceof Error ? error.message : String(error)}`,
      region.coversWholeDocument,
    )
  }

  const outcome = cadesVerify(cms, { content: region.signedBytes })
  if (!outcome.valid) return failed(outcome.reason, region.coversWholeDocument)

  const warnings: (CadesWarning | PadesWarning)[] = [...outcome.warnings]
  if (!region.coversWholeDocument) {
    warnings.push({
      code: 'partial-coverage',
      message:
        'İmza belgenin tamamını kapsamıyor — imzadan sonra içerik eklenmiş. ' +
        'Kapsam dışındaki bölüm imzalanmamıştır.',
    })
  }

  // ── Seviye ─────────────────────────────────────────────────────────────
  const key = vriKey(region.contents)
  const hasVri = dss?.vriKeys.includes(key) ?? false
  const contentsAt = region.range[1] ?? 0
  // Bu imzadan SONRA atılmış geçerli bir belge damgası: `/Contents`i daha
  // ileride olan damga, artımlı güncelleme sırası gereği sonradan gelmiştir.
  const laterStamp = stamps.some((stamp) => stamp.result.valid && stamp.contentsAt > contentsAt)
  for (const stamp of stamps) {
    if (!stamp.result.valid) {
      warnings.push({
        code: 'document-timestamp-invalid',
        message: `Belge zaman damgası doğrulanamadı: ${stamp.result.reason ?? 'bilinmeyen neden'}`,
      })
    }
  }
  if (dss !== undefined && !hasVri) {
    warnings.push({
      code: 'vri-missing',
      message:
        'Belgede DSS var ama bu imza için /VRI girdisi yok; ' +
        'malzemenin bu imzaya ait olduğu belgede yazılı değil.',
    })
  }
  const level = resolveLevel(outcome.timestamps, dss, laterStamp)

  const reasonText = textEntry(document, entry.dictionary, 'Reason')
  const location = textEntry(document, entry.dictionary, 'Location')
  return {
    ...base,
    valid: true,
    signer: outcome.signer,
    ...(outcome.signingTime === undefined ? {} : { signingTime: outcome.signingTime }),
    ...(reasonText === undefined ? {} : { reasonText }),
    ...(location === undefined ? {} : { location }),
    coversWholeDocument: region.coversWholeDocument,
    level,
    hasVri,
    timestamps: outcome.timestamps,
    warnings,
  }
}

/**
 * Seviyeyi belirler.
 *
 * Basamaklar atlanmıyor: DSS varken imza zaman damgası yoksa seviye B-B
 * kalır. ETSI, B-LT'nin B-T üzerine kurulmasını şart koşuyor ve gerekçesi
 * pratik: imza zamanı kanıtlanmamışsa, iptal kanıtının "imza anında"
 * geçerli olduğunu söylemek bir şey ifade etmez.
 */
const resolveLevel = (
  timestamps: readonly CadesTimestampResult[],
  dss: DocumentSecurityStore | undefined,
  laterDocumentTimestamp: boolean,
): PadesLevel => {
  const hasSignatureTimestamp = timestamps.some(
    (stamp) => stamp.kind === 'signature' && stamp.valid,
  )
  if (!hasSignatureTimestamp) return 'B-B'

  const hasMaterial =
    dss !== undefined && dss.certificates.length + dss.ocspResponses.length + dss.crls.length > 0
  if (!hasMaterial) return 'B-T'

  return laterDocumentTimestamp ? 'B-LTA' : 'B-LT'
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
