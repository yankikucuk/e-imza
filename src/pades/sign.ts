import type { KeyObject } from 'node:crypto'

import type { CadesSignaturePolicy, SignerLocation } from '../cades/attributes.js'
import type { CadesCommitmentType } from '../cades/constants.js'
import { cadesComplete, cadesPrepare, cadesSignWithKey } from '../cades/sign.js'
import { concat, toHex, utf8 } from '../core/bytes.js'
import { SigningError } from '../core/errors.js'
import { catalog, firstPage, readPdf, resolve, type PdfDocument } from '../pdf/document.js'
import {
  buildIncrementalUpdate,
  serializePdfObject,
  type PdfIndirectObject,
} from '../pdf/incremental.js'
import { dictEntry, indexOfSequence, type PdfObject } from '../pdf/object.js'
import type { CmsDigest } from '../pki/cms-build.js'

/**
 * PAdES — PDF imzası (ETSI EN 319 142).
 *
 * PDF'e gömülen şey **ayrık bir CAdES imzasıdır**; bu yüzden PAdES kendi
 * kriptografisini getirmiyor, {@link ../cades/sign.js | CAdES katmanının}
 * üstüne oturuyor. Getirdiği şey PDF'e özgü olan kısım: artımlı güncelleme,
 * imza sözlüğü ve `/ByteRange` hesabı.
 *
 * ## Özgün baytlara dokunulmaz
 *
 * İmza dosyanın SONUNA eklenir, eski çapraz başvuru `/Prev` ile zincire
 * bağlanır. Daha önce atılmış imzalar bu yüzden bozulmaz — ve aynı belgeye
 * üst üste imza atılabilmesinin nedeni budur.
 */

/** İmzalayanın kimlik malzemesi. */
export interface PadesSignerInput {
  readonly certificate: Uint8Array
  readonly chain?: readonly Uint8Array[]
}

/** {@link padesSign} ve {@link padesPrepare} için ortak seçenekler. */
export interface PadesSignatureOptions {
  /** İmzalanacak PDF. */
  readonly pdf: Uint8Array
  readonly signer: PadesSignerInput
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digest?: CmsDigest
  /** İmza zamanı; `null` verilirse `/M` ve `signingTime` yazılmaz. */
  readonly signingTime?: Date | null
  /** İmza gerekçesi — `/Reason`. */
  readonly reason?: string
  /** İmzanın atıldığı yer — `/Location`. */
  readonly location?: string
  /** İmzalayanın adı — `/Name`. */
  readonly name?: string
  /** İletişim bilgisi — `/ContactInfo`. */
  readonly contactInfo?: string
  readonly policy?: CadesSignaturePolicy | 'implied'
  readonly commitmentType?: CadesCommitmentType
  readonly signerLocation?: SignerLocation
  /**
   * İmza için ayrılacak yer (onaltılık karakter sayısı). Varsayılan 16384,
   * yani 8 KB imza.
   *
   * PDF'te imzanın boyutu **imza atılmadan önce** ayrılmak zorunda: yer
   * ayrılmadan `/ByteRange` hesaplanamaz, `/ByteRange` olmadan imzalanacak
   * baytlar belli olmaz. Zincir ve zaman damgası gömülecekse artırın;
   * ayrılan yer imzadan büyükse kalanı sıfırla doldurulur.
   */
  readonly signatureSpace?: number
}

/** {@link padesSign} seçenekleri. */
export interface PadesSignOptions extends PadesSignatureOptions {
  readonly privateKey: KeyObject
}

/** Dışarıda imzalanmayı bekleyen PDF imzası. */
export interface PendingPadesSignature {
  /** İmzalanacak baytlar — `/ByteRange`ın gösterdiği iki dilimin birleşimi. */
  readonly dataToSign: Uint8Array
  /** {@link dataToSign} baytlarının özeti. */
  readonly digest: Uint8Array
  /** RSA PKCS#1 v1.5 için DER `DigestInfo`; EC anahtarlarda `undefined`. */
  readonly digestInfo?: Uint8Array
  readonly digestAlgorithm: CmsDigest
  readonly keyKind: 'rsa' | 'ec'
  /** @internal */
  readonly finish: (cms: Uint8Array) => Uint8Array
  /** @internal */
  readonly completeCades: (signature: Uint8Array) => Uint8Array
}

const DEFAULT_SPACE = 16384

/**
 * PDF'i PAdES ile imzalar.
 *
 * @param options - {@link PadesSignOptions}
 * @returns İmzalanmış PDF
 *
 * @example
 * ```ts
 * const { privateKey, certificate, chain } = loadPkcs12(p12, sifre)
 * const imzali = padesSign({
 *   pdf: readFileSync('belge.pdf'),
 *   signer: { certificate, chain },
 *   privateKey,
 *   reason: 'Onay',
 *   location: 'İstanbul',
 * })
 * ```
 */
export const padesSign = (options: PadesSignOptions): Uint8Array => {
  const pending = padesPrepare(options)
  const cms = pending.completeCades(cadesSignWithKeyFor(pending, options.privateKey))
  return pending.finish(cms)
}

/** Bekleyen imzayı yerel anahtarla imzalar. */
const cadesSignWithKeyFor = (pending: PendingPadesSignature, privateKey: KeyObject): Uint8Array =>
  cadesSignWithKey(
    {
      dataToSign: pending.dataToSign,
      digest: pending.digest,
      digestAlgorithm: pending.digestAlgorithm,
      keyKind: pending.keyKind,
      build: () => new Uint8Array(0),
      ...(pending.digestInfo === undefined ? {} : { digestInfo: pending.digestInfo }),
    },
    privateKey,
  )

/**
 * İmzayı, imza değeri dışında tamamen hazırlar.
 *
 * @param options - {@link PadesSignatureOptions}
 * @returns İmzalanmayı bekleyen imza
 */
export const padesPrepare = (options: PadesSignatureOptions): PendingPadesSignature => {
  const space = options.signatureSpace ?? DEFAULT_SPACE
  if (space < 1024 || space % 2 !== 0) {
    throw new SigningError('İmza için ayrılan yer en az 1024 ve çift sayıda olmalı.')
  }

  const document = readPdf(options.pdf)
  const root = catalog(document)
  const page = firstPage(document)

  const signatureNumber = document.size
  const annotationNumber = document.size + 1
  const signingTime = options.signingTime === undefined ? new Date() : options.signingTime

  // ── İmza sözlüğü ───────────────────────────────────────────────────────
  // `/ByteRange` ve `/Contents` SABİT genişlikte yer tutucularla yazılır:
  // gerçek değerler ancak yerleşim bittikten sonra bilinir ve genişlik
  // değişirse tüm konumlar kayar.
  const byteRangePlaceholder = `[${'0'.repeat(10)} ${'0'.repeat(10)} ${'0'.repeat(10)} ${'0'.repeat(10)}]`
  const signatureBody = concat(
    utf8('<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached\n'),
    utf8(`/ByteRange ${byteRangePlaceholder}\n`),
    utf8(`/Contents <${'0'.repeat(space)}>\n`),
    ...(signingTime === null ? [] : [utf8(`/M ${pdfDate(signingTime)}\n`)]),
    ...(options.reason === undefined ? [] : [utf8(`/Reason ${pdfText(options.reason)}\n`)]),
    ...(options.location === undefined ? [] : [utf8(`/Location ${pdfText(options.location)}\n`)]),
    ...(options.name === undefined ? [] : [utf8(`/Name ${pdfText(options.name)}\n`)]),
    ...(options.contactInfo === undefined
      ? []
      : [utf8(`/ContactInfo ${pdfText(options.contactInfo)}\n`)]),
    utf8('>>'),
  )

  // ── Görünmez imza alanı ────────────────────────────────────────────────
  // PAdES'te görünmez imza bile bir sayfaya bağlanmak zorunda; sıfır
  // boyutlu dikdörtgen "görünmez" demenin standart yolu.
  const annotationBody = utf8(
    '<< /Type /Annot /Subtype /Widget /FT /Sig /Ff 0 ' +
      '/Rect [0 0 0 0] /F 132 ' +
      `/T ${pdfText(`Imza-${String(signatureNumber)}`)} ` +
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
    original: options.pdf,
    previousStartXref: document.startXref,
    rootReference: root.reference,
    objects,
    size: document.size + 2,
    ...(documentId === undefined ? {} : { extraTrailer: new Map([['ID', documentId]]) }),
  })

  // ── /ByteRange hesabı ──────────────────────────────────────────────────
  const contentsMarker = utf8('/Contents <')
  const markerAt = indexOfSequence(assembled, contentsMarker, options.pdf.length)
  if (markerAt === -1) throw new SigningError('PDF: imza yer tutucusu bulunamadı.')
  const openAngle = markerAt + contentsMarker.length - 1
  const afterCloseAngle = openAngle + space + 2

  const byteRange = [0, openAngle, afterCloseAngle, assembled.length - afterCloseAngle]
  const patched = patchByteRange(assembled, byteRange, options.pdf.length)

  // İmzalanan baytlar: `/Contents <…>` dışındaki her şey.
  const dataToSign = concat(patched.subarray(0, byteRange[1]), patched.subarray(byteRange[2]))

  // Ayrık CAdES imzası — `/SubFilter /ETSI.CAdES.detached` tam olarak bunu
  // söylüyor.
  const cades = cadesPrepare({
    data: dataToSign,
    signer: options.signer,
    attached: false,
    digest: options.digest ?? 'sha256',
    signingTime,
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    ...(options.commitmentType === undefined ? {} : { commitmentType: options.commitmentType }),
    ...(options.signerLocation === undefined ? {} : { signerLocation: options.signerLocation }),
  })

  return {
    dataToSign: cades.dataToSign,
    digest: cades.digest,
    ...(cades.digestInfo === undefined ? {} : { digestInfo: cades.digestInfo }),
    digestAlgorithm: cades.digestAlgorithm,
    keyKind: cades.keyKind,
    completeCades: (signature: Uint8Array): Uint8Array => cadesComplete(cades, signature),
    finish: (cms: Uint8Array): Uint8Array => {
      if (cms.length * 2 > space) {
        throw new SigningError(
          `İmza ayrılan yere sığmıyor: ${String(cms.length * 2)} > ${String(space)} onaltılık karakter. ` +
            'signatureSpace seçeneğini artırın.',
        )
      }
      // Yer tutucu zaten sıfırlarla dolu olduğu için `padEnd` çıktıyı
      // DEĞİŞTİRMİYOR — savunma amaçlı duruyor: yer tutucu ileride başka
      // bir karakterle doldurulursa imzadan artan bölge çöp kalmasın.
      // Mutasyonla ölçüldü: kaldırılması hiçbir testi düşürmüyor çünkü
      // gözlemlenebilir bir farkı yok.
      const hex = utf8(toHex(cms).padEnd(space, '0'))
      const out = new Uint8Array(patched)
      out.set(hex, openAngle + 1)
      return out
    },
  }
}

/**
 * Dışarıda üretilmiş imza değerini yerine koyar.
 *
 * @param pending - {@link padesPrepare} çıktısı
 * @param signature - Ham imza baytları (CAdES kuralı: ECDSA'da DER)
 * @returns İmzalanmış PDF
 */
export const padesComplete = (pending: PendingPadesSignature, signature: Uint8Array): Uint8Array =>
  pending.finish(pending.completeCades(signature))

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
const pdfDate = (when: Date): string => {
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
const pdfText = (text: string): string => {
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
