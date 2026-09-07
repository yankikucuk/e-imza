import { createHash } from 'node:crypto'

import { toHex } from '../core/bytes.js'
import { SigningError } from '../core/errors.js'
import { catalog, readPdf, resolve, streamData, type PdfDocument } from '../pdf/document.js'
import {
  buildIncrementalUpdate,
  serializePdfObject,
  type PdfIndirectObject,
} from '../pdf/incremental.js'
import { dictEntry, type PdfObject } from '../pdf/object.js'

import { findSignatures } from './locate.js'
import { pdfDate } from './placement.js'

/**
 * DSS — Document Security Store (ISO 32000-2 §12.8.4.3, ETSI EN 319 142-1).
 *
 * PAdES-LT'nin tamamı budur: doğrulayanın ihtiyaç duyacağı sertifikalar ve
 * iptal kanıtları belgenin İÇİNE, artımlı bir güncellemeyle konur. Beş yıl
 * sonra "bu sertifika imza anında iptal edilmiş miydi?" sorusunun cevabı
 * hiçbir OCSP yanıtlayıcısında bulunmaz; belgede bulunur.
 *
 * XAdES'teki `CertificateValues` + `RevocationValues` ikilisinin PDF
 * karşılığı.
 */

/** DSS'e konacak doğrulama malzemesi. */
export interface ValidationMaterial {
  /** Sertifikalar (DER) — zincirin tamamı, uçtan köke. */
  readonly certificates?: readonly Uint8Array[]
  /** OCSP yanıtları — tam `OCSPResponse` DER'i, `BasicOCSPResponse` değil. */
  readonly ocspResponses?: readonly Uint8Array[]
  /** Sertifika iptal listeleri (`CertificateList` DER'i). */
  readonly crls?: readonly Uint8Array[]
}

/** Belgeden okunmuş DSS içeriği. */
export interface DocumentSecurityStore {
  readonly certificates: readonly Uint8Array[]
  readonly ocspResponses: readonly Uint8Array[]
  readonly crls: readonly Uint8Array[]
  /** `/VRI` anahtarları — imza başına bir tane, onaltılık büyük harf. */
  readonly vriKeys: readonly string[]
}

/**
 * Bir imzanın `/VRI` anahtarını hesaplar.
 *
 * ISO 32000-2: anahtar, imzanın SHA-1 özetinin büyük harfli onaltılık
 * yazımıdır. "İmza" burada `/Contents` dizesinin **dosyada durduğu hâlidir**
 * — yani DER'in ardındaki sıfır dolgusu DA dahil.
 *
 * Bu, kelimesi kelimesine tek okunuş değil: DER'i kırpıp yalnız CMS'i
 * özetlemek de savunulabilir ve spesifikasyon bunu netleştirmiyor. Dolgulu
 * hâl seçildi çünkü yaygın uygulamalar (iText'in `LtvVerification`'ı,
 * PDFBox tabanlı ETSI DSS) `/Contents` bayt dizesini olduğu gibi özetliyor
 * ve `/VRI`nin tek işlevi başka bir doğrulayıcıyla EŞLEŞMEK. Kendi
 * okuyucumuzla tutarlı olmak yetmez.
 *
 * @param contents - `/Contents` dizesinin çözülmüş baytları
 * @returns Büyük harfli onaltılık SHA-1
 */
export const vriKey = (contents: Uint8Array): string =>
  toHex(new Uint8Array(createHash('sha1').update(contents).digest())).toUpperCase()

/**
 * Belgeye DSS ekleyerek PAdES-LT üretir.
 *
 * Var olan bir DSS varsa **korunur ve genişletilir**: içindeki nesnelere
 * yapılan başvurular olduğu gibi taşınır, yenileri eklenir. Üzerine yazmak,
 * daha önce eklenmiş iptal kanıtını silmek olurdu.
 *
 * @param pdf - İmzalı PDF
 * @param material - {@link ValidationMaterial}
 * @param options - `vriTime`: `/VRI`ye yazılacak zaman; `null` yazmaz
 * @returns DSS eklenmiş PDF
 * @throws {SigningError} Belgede hiç imza yoksa
 */
export const addDocumentSecurityStore = (
  pdf: Uint8Array,
  material: ValidationMaterial,
  options: { readonly vriTime?: Date | null } = {},
): Uint8Array => {
  const document = readPdf(pdf)
  const root = catalog(document)
  const signatures = findSignatures(document)
  if (signatures.length === 0) {
    throw new SigningError("PDF'te imza yok; DSS eklemenin anlamı olmaz.")
  }

  const certificates = unique(material.certificates ?? [])
  const ocspResponses = unique(material.ocspResponses ?? [])
  const crls = unique(material.crls ?? [])
  if (certificates.length + ocspResponses.length + crls.length === 0) {
    throw new SigningError('DSS için en az bir sertifika, OCSP yanıtı ya da CRL gerekli.')
  }

  // Nesne numaraları: DSS sözlüğü, ardından her malzeme için birer akış.
  let next = document.size
  const dssNumber = next++
  const objects: PdfIndirectObject[] = []

  /** Malzemeyi akış nesnelerine döker ve başvurularını verir. */
  const streams = (items: readonly Uint8Array[]): PdfObject[] =>
    items.map((der) => {
      const number = next++
      objects.push({ number, body: rawStream(der) })
      return { kind: 'ref', number, generation: 0 }
    })

  const certRefs = streams(certificates)
  const ocspRefs = streams(ocspResponses)
  const crlRefs = streams(crls)

  // Var olan DSS'in başvuruları önce gelir: eskiyi kaybetmemek için.
  const existing = readDssReferences(document, root.object)
  const entries = new Map<string, PdfObject>()
  const merged = {
    Certs: [...existing.certs, ...certRefs],
    OCSPs: [...existing.ocsps, ...ocspRefs],
    CRLs: [...existing.crls, ...crlRefs],
  }
  for (const [key, items] of Object.entries(merged)) {
    if (items.length > 0) entries.set(key, { kind: 'array', items })
  }

  // `/VRI` — imza başına bir girdi. Aynı malzemeyi hepsine bağlıyoruz:
  // hangi kanıtın hangi imzaya ait olduğunu çağıran biliyor, biz değil;
  // yanlış eşleştirmektense hepsini göstermek doğru.
  const vriTime = options.vriTime === undefined ? new Date() : options.vriTime
  const vri = new Map<string, PdfObject>()
  for (const signature of signatures) {
    const contents = resolve(document, dictEntry(signature.dictionary, 'Contents'))
    if (contents?.kind !== 'string') continue
    const perSignature = new Map<string, PdfObject>()
    if (merged.Certs.length > 0) {
      perSignature.set('Cert', { kind: 'array', items: merged.Certs })
    }
    if (merged.OCSPs.length > 0) {
      perSignature.set('OCSP', { kind: 'array', items: merged.OCSPs })
    }
    if (merged.CRLs.length > 0) {
      perSignature.set('CRL', { kind: 'array', items: merged.CRLs })
    }
    if (vriTime !== null) {
      perSignature.set('TU', { kind: 'string', value: pdfDateBytes(vriTime), hex: false })
    }
    vri.set(vriKey(contents.value), { kind: 'dict', entries: perSignature })
  }
  if (vri.size > 0) entries.set('VRI', { kind: 'dict', entries: vri })

  objects.push({ number: dssNumber, body: serializePdfObject({ kind: 'dict', entries }) })
  objects.push({
    number: root.reference,
    body: updatedCatalog(root.object, dssNumber),
  })

  const documentId = document.trailer.get('ID')
  return buildIncrementalUpdate({
    original: pdf,
    previousStartXref: document.startXref,
    rootReference: root.reference,
    objects,
    size: next,
    ...(documentId === undefined ? {} : { extraTrailer: new Map([['ID', documentId]]) }),
  })
}

/**
 * Belgedeki DSS'i okur.
 *
 * @param pdf - PDF
 * @returns DSS içeriği; `/DSS` yoksa `undefined`
 */
export const readDocumentSecurityStore = (pdf: Uint8Array): DocumentSecurityStore | undefined => {
  const document = readPdf(pdf)
  return readDss(document, catalog(document).object)
}

/** Okunmuş belgeden DSS'i çıkarır. */
export const readDss = (
  document: PdfDocument,
  root: PdfObject,
): DocumentSecurityStore | undefined => {
  const dss = resolve(document, dictEntry(root, 'DSS'))
  if (dss?.kind !== 'dict') return undefined

  const collect = (key: string): readonly Uint8Array[] => {
    const array = resolve(document, dictEntry(dss, key))
    if (array?.kind !== 'array') return []
    const out: Uint8Array[] = []
    for (const item of array.items) {
      const object = resolve(document, item)
      if (object?.kind !== 'stream') continue
      try {
        out.push(streamData(object))
      } catch {
        // Çözülemeyen akış atlanıyor: DSS'in geri kalanı hâlâ kullanışlı.
      }
    }
    return out
  }

  const vriDict = resolve(document, dictEntry(dss, 'VRI'))
  const vriKeys = vriDict?.kind === 'dict' ? [...vriDict.entries.keys()] : []

  return {
    certificates: collect('Certs'),
    ocspResponses: collect('OCSPs'),
    crls: collect('CRLs'),
    vriKeys,
  }
}

/** Var olan DSS dizilerindeki BAŞVURULARI verir (içeriği çözmeden). */
const readDssReferences = (
  document: PdfDocument,
  root: PdfObject,
): { certs: PdfObject[]; ocsps: PdfObject[]; crls: PdfObject[] } => {
  const dss = resolve(document, dictEntry(root, 'DSS'))
  const pick = (key: string): PdfObject[] => {
    if (dss?.kind !== 'dict') return []
    const array = resolve(document, dictEntry(dss, key))
    return array?.kind === 'array' ? array.items.filter((item) => item.kind === 'ref') : []
  }
  return { certs: pick('Certs'), ocsps: pick('OCSPs'), crls: pick('CRLs') }
}

/**
 * Kataloğa `/DSS` ve Adobe uzantı bildirimini ekler.
 *
 * `/Extensions /ADBE /ExtensionLevel 5`: DSS ve VRI, ISO 32000-1'de yok —
 * "Adobe Supplement to ISO 32000, ExtensionLevel 5" ile geldiler. PDF 2.0
 * öncesi görüntüleyiciler bu bildirimi görmeden DSS'i yok sayabilir.
 */
const updatedCatalog = (root: PdfObject, dssNumber: number): Uint8Array => {
  if (root.kind !== 'dict') throw new SigningError('PDF: katalog sözlük değil.')
  const entries = new Map(root.entries)
  entries.set('DSS', { kind: 'ref', number: dssNumber, generation: 0 })

  const extensions = entries.get('Extensions')
  const outer =
    extensions?.kind === 'dict' ? new Map(extensions.entries) : new Map<string, PdfObject>()
  if (!outer.has('ADBE')) {
    outer.set('ADBE', {
      kind: 'dict',
      entries: new Map<string, PdfObject>([
        ['BaseVersion', { kind: 'name', value: '1.7' }],
        ['ExtensionLevel', { kind: 'number', value: 5 }],
      ]),
    })
  }
  entries.set('Extensions', { kind: 'dict', entries: outer })
  return serializePdfObject({ kind: 'dict', entries })
}

/**
 * Süzgeçsiz akış nesnesi.
 *
 * Sıkıştırılmıyor: bir sertifika zaten bir kilobayt ve DER neredeyse
 * sıkışmaz. Kazanç yok, ama süzgeç eklemek okuma tarafında bir başarısızlık
 * yolu daha açardı.
 */
const rawStream = (der: Uint8Array): Uint8Array =>
  serializePdfObject({
    kind: 'stream',
    entries: new Map<string, PdfObject>([['Length', { kind: 'number', value: der.length }]]),
    raw: der,
  })

/** Bayt dizilerini içeriğe göre tekilleştirir. */
const unique = (items: readonly Uint8Array[]): readonly Uint8Array[] => {
  const seen = new Set<string>()
  const out: Uint8Array[] = []
  for (const item of items) {
    const key = toHex(item)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(item)
  }
  return out
}

/** `/TU` için PDF tarih dizesi — ayraçsız baytlar. */
const pdfDateBytes = (when: Date): Uint8Array => {
  const text = pdfDate(when)
  const inner = text.slice(1, -1)
  const out = new Uint8Array(inner.length)
  for (let i = 0; i < inner.length; i += 1) out[i] = inner.charCodeAt(i)
  return out
}
