import { createHash } from 'node:crypto'

import { fromUtf8, toBase64, utf8 } from '../core/bytes.js'
import { SigningError, VerificationError } from '../core/errors.js'
import {
  childNamed,
  getAttributeValue,
  textContent,
  walkElements,
  type XmlAttribute,
  type XmlElement,
} from '../xml/node.js'
import { parseXml } from '../xml/parse.js'
import { serializeXml } from '../xml/serialize.js'
import { createZip, peekFirstEntry, readZip, type ZipEntry } from '../zip/archive.js'

/**
 * ASiC — imzalı konteyner (ETSI EN 319 162-1).
 *
 * İmza üretmez, **paketler**. İçine konan imza XAdES ya da CAdES olabilir;
 * konteyner onların içeriğine bakmaz. Bu ayrım standardın kendi ayrımı:
 * ASiC bir imza biçimi değil, bir taşıma biçimidir.
 *
 * İki tür var:
 * - **ASiC-S** (simple) — tek veri nesnesi, tek imza. Bir faturayı ve
 *   imzasını tek dosyada taşımak için.
 * - **ASiC-E** (extended) — birden çok veri nesnesi ve imza. CAdES ile
 *   kullanıldığında hangi imzanın hangi dosyaları kapsadığı bir
 *   `ASiCManifest` ile bildirilir.
 */

/** ASiC ad alanı (EN 319 162-1). */
const ASIC_NAMESPACE = 'http://uri.etsi.org/02918/v1.2.1#'
const DSIG_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#'

/** Konteyner türü. */
export type AsicType = 'asic-s' | 'asic-e'

/** Tür → `mimetype` içeriği. */
export const ASIC_MIME_TYPE: Readonly<Record<AsicType, string>> = {
  'asic-s': 'application/vnd.etsi.asic-s+zip',
  'asic-e': 'application/vnd.etsi.asic-e+zip',
}

/** İmza biçimi. */
export type AsicSignatureFormat = 'cades' | 'xades'

/** Konteynere konacak bir veri dosyası. */
export interface AsicDataFile {
  readonly name: string
  readonly data: Uint8Array
}

/** Konteynere konacak bir imza. */
export interface AsicSignature {
  readonly format: AsicSignatureFormat
  /** İmza baytları — CAdES'te DER CMS, XAdES'te XML metni. */
  readonly data: Uint8Array
  /**
   * Bu imzanın kapsadığı veri dosyalarının adları.
   *
   * Yalnızca ASiC-E + CAdES'te anlamlı: `ASiCManifest` bu listeye göre
   * üretilir. Verilmezse bütün veri dosyaları kapsanmış sayılır.
   */
  readonly covers?: readonly string[]
}

/** {@link createAsic} seçenekleri. */
export interface CreateAsicOptions {
  readonly type: AsicType
  readonly dataFiles: readonly AsicDataFile[]
  readonly signatures: readonly AsicSignature[]
  /** `ASiCManifest` özet algoritması; varsayılan `sha256`. */
  readonly digest?: 'sha256' | 'sha384' | 'sha512'
}

/** Özet algoritması → XMLDSig URI. */
const DIGEST_URI: Readonly<Record<string, string>> = {
  sha256: 'http://www.w3.org/2001/04/xmlenc#sha256',
  sha384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  sha512: 'http://www.w3.org/2001/04/xmlenc#sha512',
}

/**
 * ASiC konteyneri üretir.
 *
 * @param options - {@link CreateAsicOptions}
 * @returns Konteyner baytları (ZIP)
 * @throws {SigningError} Tür kısıtları ihlal edilirse
 *
 * @example
 * ```ts
 * const konteyner = createAsic({
 *   type: 'asic-s',
 *   dataFiles: [{ name: 'fatura.xml', data: faturaBaytlari }],
 *   signatures: [{ format: 'cades', data: cadesImzasi }],
 * })
 * ```
 */
export const createAsic = (options: CreateAsicOptions): Uint8Array => {
  if (options.dataFiles.length === 0) {
    throw new SigningError('ASiC konteyneri en az bir veri dosyası içermeli.')
  }
  if (options.signatures.length === 0) {
    throw new SigningError('ASiC konteyneri en az bir imza içermeli.')
  }
  // ASiC-S kısıtları standardın kendi kısıtları; esnetmek, okuyucuların
  // konteyneri reddetmesine yol açar.
  if (options.type === 'asic-s') {
    if (options.dataFiles.length > 1) {
      throw new SigningError('ASiC-S tek veri dosyası taşır; birden çoğu için ASiC-E kullanın.')
    }
    if (options.signatures.length > 1) {
      throw new SigningError('ASiC-S tek imza taşır; birden çoğu için ASiC-E kullanın.')
    }
  }
  for (const file of options.dataFiles) {
    if (file.name.startsWith('META-INF/') || file.name === 'mimetype') {
      throw new SigningError(`Veri dosyası adı ayrılmış: "${file.name}"`)
    }
  }

  const digest = options.digest ?? 'sha256'
  const entries: ZipEntry[] = [
    // `mimetype` İLK ve SIKIŞTIRILMAMIŞ olmalı. Bu sayede konteynerin türü
    // ZIP açılmadan, dosyanın ilk baytlarına bakılarak anlaşılıyor.
    { name: 'mimetype', data: utf8(ASIC_MIME_TYPE[options.type]), stored: true },
    ...options.dataFiles.map((file) => ({ name: file.name, data: file.data })),
  ]

  options.signatures.forEach((signature, index) => {
    const suffix = options.type === 'asic-s' ? '' : String(index + 1).padStart(3, '0')
    if (signature.format === 'cades') {
      const name = `META-INF/signature${suffix}.p7s`
      entries.push({ name, data: signature.data })
      // ASiC-E + CAdES: hangi imzanın neyi kapsadığı manifest ile bildirilir.
      // ASiC-S'te tek dosya ve tek imza var, manifest gerekmiyor.
      if (options.type === 'asic-e') {
        const covered = signature.covers ?? options.dataFiles.map((file) => file.name)
        entries.push({
          name: `META-INF/ASiCManifest${suffix}.xml`,
          data: utf8(buildManifest(name, covered, options.dataFiles, digest)),
        })
      }
    } else {
      entries.push({ name: `META-INF/signatures${suffix}.xml`, data: signature.data })
    }
  })

  return createZip(entries)
}

/** `ASiCManifest` belgesini üretir. */
const buildManifest = (
  signatureName: string,
  covered: readonly string[],
  dataFiles: readonly AsicDataFile[],
  digest: string,
): string => {
  const attribute = (name: string, value: string): XmlAttribute => ({
    namespace: undefined,
    prefix: undefined,
    localName: name,
    value,
  })
  const element = (
    namespace: string,
    prefix: string,
    localName: string,
    children: readonly XmlElement[] = [],
    attributes: readonly XmlAttribute[] = [],
    declarations: readonly { prefix: string; uri: string }[] = [],
  ): XmlElement => ({
    kind: 'element',
    namespace,
    prefix,
    localName,
    namespaceDeclarations: declarations,
    attributes,
    children,
  })

  const references = covered.map((name) => {
    const file = dataFiles.find((candidate) => candidate.name === name)
    if (file === undefined) {
      throw new SigningError(`İmzanın kapsadığı dosya konteynerde yok: "${name}"`)
    }
    const value = new Uint8Array(createHash(digest).update(Buffer.from(file.data)).digest())
    return element(
      ASIC_NAMESPACE,
      'asic',
      'DataObjectReference',
      [
        element(
          DSIG_NAMESPACE,
          'ds',
          'DigestMethod',
          [],
          [attribute('Algorithm', DIGEST_URI[digest] ?? '')],
        ),
        {
          ...element(DSIG_NAMESPACE, 'ds', 'DigestValue'),
          children: [{ kind: 'text', value: toBase64(value) }],
        },
      ],
      [attribute('URI', name)],
    )
  })

  const root = element(
    ASIC_NAMESPACE,
    'asic',
    'ASiCManifest',
    [
      element(
        ASIC_NAMESPACE,
        'asic',
        'SigReference',
        [],
        [attribute('URI', signatureName), attribute('MimeType', 'application/pkcs7-signature')],
      ),
      ...references,
    ],
    [],
    [
      { prefix: 'asic', uri: ASIC_NAMESPACE },
      { prefix: 'ds', uri: DSIG_NAMESPACE },
    ],
  )
  return serializeXml({ kind: 'document', root, prolog: [], epilog: [] })
}

/** Konteynerdeki bir imza ve kapsamı. */
export interface AsicSignatureEntry {
  readonly name: string
  readonly format: AsicSignatureFormat
  readonly data: Uint8Array
  /** İlgili `ASiCManifest` varsa, kapsadığı dosyalar ve özet durumları. */
  readonly manifest?: AsicManifestEntry
}

/** `ASiCManifest` çözümlemesi. */
export interface AsicManifestEntry {
  readonly name: string
  /** Manifestin gösterdiği imza dosyası. */
  readonly signatureReference: string
  readonly references: readonly {
    readonly uri: string
    /** Dosya konteynerde var mı. */
    readonly present: boolean
    /** Özet manifestte yazandan farklıysa `false`. */
    readonly digestMatches: boolean
  }[]
}

/** {@link readAsic} sonucu. */
export interface AsicContainer {
  readonly type: AsicType
  /** `mimetype` girdisinin ham içeriği. */
  readonly mimeType: string
  readonly dataFiles: readonly AsicDataFile[]
  readonly signatures: readonly AsicSignatureEntry[]
}

/**
 * ASiC konteynerini okur.
 *
 * `ASiCManifest` varsa referans edilen dosyaların özetleri **yeniden
 * hesaplanıp karşılaştırılır**. Manifesti okuyup özetleri doğrulamamak,
 * imzanın kapsadığını iddia ettiği dosyanın gerçekten o dosya olduğunu
 * varsaymak olurdu.
 *
 * @param bytes - Konteyner baytları
 * @returns Çözümlenmiş konteyner
 * @throws {VerificationError} Konteyner ASiC değilse ya da okunamazsa
 */
export const readAsic = (bytes: Uint8Array): AsicContainer => {
  const first = peekFirstEntry(bytes)
  if (first?.name !== 'mimetype') {
    throw new VerificationError('ASiC değil: ilk girdi sıkıştırılmamış "mimetype" olmalı.')
  }
  const mimeType = fromUtf8(first.data).trim()
  const type = (Object.keys(ASIC_MIME_TYPE) as AsicType[]).find(
    (candidate) => ASIC_MIME_TYPE[candidate] === mimeType,
  )
  if (type === undefined) {
    throw new VerificationError(`ASiC değil: tanınmayan mimetype "${mimeType}"`)
  }

  let entries: readonly ZipEntry[]
  try {
    entries = readZip(bytes)
  } catch (error) {
    throw new VerificationError(
      `Konteyner okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  const dataFiles: AsicDataFile[] = []
  const signatures: { name: string; format: AsicSignatureFormat; data: Uint8Array }[] = []
  const manifests = new Map<string, ZipEntry>()

  for (const entry of entries) {
    if (entry.name === 'mimetype') continue
    if (!entry.name.startsWith('META-INF/')) {
      dataFiles.push({ name: entry.name, data: entry.data })
      continue
    }
    const leaf = entry.name.slice('META-INF/'.length)
    if (/^signature.*\.p7s$/.test(leaf)) {
      signatures.push({ name: entry.name, format: 'cades', data: entry.data })
    } else if (/^signatures.*\.xml$/.test(leaf)) {
      signatures.push({ name: entry.name, format: 'xades', data: entry.data })
    } else if (/^ASiCManifest.*\.xml$/.test(leaf)) {
      manifests.set(entry.name, entry)
    }
  }

  const parsed = [...manifests.values()].map((entry) => readManifest(entry, dataFiles))
  return {
    type,
    mimeType,
    dataFiles,
    signatures: signatures.map((signature) => {
      const manifest = parsed.find((item) => item.signatureReference === signature.name)
      return {
        ...signature,
        ...(manifest === undefined ? {} : { manifest }),
      }
    }),
  }
}

/** `ASiCManifest` belgesini çözer ve özetleri doğrular. */
const readManifest = (entry: ZipEntry, dataFiles: readonly AsicDataFile[]): AsicManifestEntry => {
  const document = parseXml(fromUtf8(entry.data))
  const reference = childNamed(document.root, ASIC_NAMESPACE, 'SigReference')
  const signatureReference =
    reference === undefined ? '' : (getAttributeValue(reference, 'URI') ?? '')

  // Yerel liste değiştirilebilir; dışa açılan tip salt okunur.
  const references: {
    uri: string
    present: boolean
    digestMatches: boolean
  }[] = []
  for (const element of walkElements(document.root)) {
    if (element.namespace !== ASIC_NAMESPACE || element.localName !== 'DataObjectReference') {
      continue
    }
    const uri = getAttributeValue(element, 'URI') ?? ''
    const file = dataFiles.find((candidate) => candidate.name === uri)
    if (file === undefined) {
      references.push({ uri, present: false, digestMatches: false })
      continue
    }
    const method = childNamed(element, DSIG_NAMESPACE, 'DigestMethod')
    const value = childNamed(element, DSIG_NAMESPACE, 'DigestValue')
    const algorithm = Object.keys(DIGEST_URI).find(
      (name) =>
        DIGEST_URI[name] === (method === undefined ? '' : getAttributeValue(method, 'Algorithm')),
    )
    if (algorithm === undefined || value === undefined) {
      references.push({ uri, present: true, digestMatches: false })
      continue
    }
    const actual = toBase64(
      new Uint8Array(createHash(algorithm).update(Buffer.from(file.data)).digest()),
    )
    references.push({
      uri,
      present: true,
      digestMatches: actual === textContent(value).trim(),
    })
  }
  return { name: entry.name, signatureReference, references }
}
