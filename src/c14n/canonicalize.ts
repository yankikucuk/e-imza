import { utf8 } from '../core/bytes.js'
import { UnsupportedCanonicalizationError } from '../core/errors.js'
import {
  compareCodePoints,
  escapeAttributeValue,
  escapeCommentOrInstruction,
  escapeText,
} from '../xml/escape.js'
import {
  qualifiedName,
  XML_NAMESPACE,
  type XmlAttribute,
  type XmlDocument,
  type XmlElement,
  type XmlNamespaceDeclaration,
  type XmlNode,
} from '../xml/node.js'

/** Desteklenen kanonikleştirme algoritmaları. */
export type C14nAlgorithm =
  'c14n10' | 'c14n10-with-comments' | 'exc-c14n' | 'exc-c14n-with-comments'

/** Algoritma anahtarı → XMLDSig `Algorithm` özniteliğinde kullanılan URI. */
export const C14N_URI: Readonly<Record<C14nAlgorithm, string>> = {
  c14n10: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  'c14n10-with-comments': 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
  'exc-c14n': 'http://www.w3.org/2001/10/xml-exc-c14n#',
  'exc-c14n-with-comments': 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
}

/**
 * URI'yi algoritma anahtarına çevirir.
 *
 * @param uri - `Algorithm` özniteliğinden okunan URI
 * @returns Algoritma anahtarı
 * @throws {UnsupportedCanonicalizationError} URI tanınmıyorsa
 */
export const c14nAlgorithmFromUri = (uri: string): C14nAlgorithm => {
  for (const [key, value] of Object.entries(C14N_URI)) {
    if (value === uri) return key as C14nAlgorithm
  }
  throw new UnsupportedCanonicalizationError(uri)
}

/** {@link canonicalize} seçenekleri. */
export interface CanonicalizeOptions {
  /** Kullanılacak algoritma. Varsayılan `exc-c14n` — UBL-TR e-Fatura'nın kullandığı. */
  readonly algorithm?: C14nAlgorithm

  /**
   * Yalnızca bu öğe ve altı kanonikleştirilir.
   *
   * Öğe, belgenin İÇİNDEN nesne kimliğiyle verilir; kopyası değil. Ata
   * bağlamı (ad alanları, `xml:*` öznitelikleri) belgeden okunur — bu yüzden
   * bir alt ağacı tek başına kanonikleştirmek, onu belgeden koparıp ayrıca
   * ad alanı kopyalamayı gerektirmez. Kopyalamayı elle yapan uygulamalarda
   * `xmldsigjs#59` türü hatalar buradan çıkar.
   */
  readonly subset?: XmlElement

  /**
   * Çıktıdan tamamen çıkarılacak düğümler (kendileri ve alt ağaçları).
   *
   * `enveloped-signature` dönüşümü için buradadır ve dönüşümün doğru
   * anlamını verir: dönüşüm, referansı İÇEREN `ds:Signature` öğesini
   * çıkarır — belgedeki bütün imzaları değil. `xmldsigjs#49` ve `#37`
   * tam olarak bu ayrımı yapmadıkları için paralel imzayı bozuyordu.
   */
  readonly omit?: ReadonlySet<XmlNode>

  /**
   * Exclusive C14N `InclusiveNamespaces PrefixList` — bu ön ekler
   * "görünür kullanımda olmasalar da" yazılır.
   *
   * Yalnızca `exc-c14n` ailesinde anlamlıdır.
   */
  readonly inclusiveNamespacePrefixes?: readonly string[]
}

/** Çıktıda yazılacak ad alanı bildirimi. */
interface RenderedNamespace {
  readonly prefix: string
  readonly uri: string
}

const isExclusive = (algorithm: C14nAlgorithm): boolean => algorithm.startsWith('exc-')
const keepsComments = (algorithm: C14nAlgorithm): boolean => algorithm.endsWith('-with-comments')

/**
 * Kökten hedefe giden ata zincirini bulur (hedef dâhil değil).
 *
 * Karşılaştırma nesne kimliğiyle yapılır; aynı ada sahip başka bir öğe
 * yanlışlıkla eşleşmez.
 */
const findAncestors = (root: XmlElement, target: XmlElement): XmlElement[] | undefined => {
  if (root === target) return []
  for (const child of root.children) {
    if (child.kind !== 'element') continue
    const found = findAncestors(child, target)
    if (found !== undefined) return [root, ...found]
  }
  return undefined
}

/**
 * XML belgesini kanonik biçimde serileştirir.
 *
 * Uygulanan iki standart:
 * - **Canonical XML 1.0** (`REC-xml-c14n-20010315`) — `c14n10` aileleri
 * - **Exclusive XML Canonicalization 1.0** — `exc-c14n` aileleri
 *
 * @param document - Kaynak belge
 * @param options - Algoritma, alt küme, çıkarılacak düğümler
 * @returns Kanonik metin (UTF-8 olarak kodlanmaya hazır)
 *
 * @example Tüm belge
 * ```ts
 * canonicalize(doc, { algorithm: 'exc-c14n' })
 * ```
 *
 * @example İmzayı dışarıda bırakarak (enveloped-signature dönüşümü)
 * ```ts
 * canonicalize(doc, { algorithm: 'exc-c14n', omit: new Set([signatureElement]) })
 * ```
 */
export const canonicalize = (document: XmlDocument, options: CanonicalizeOptions = {}): string => {
  const algorithm = options.algorithm ?? 'exc-c14n'
  const exclusive = isExclusive(algorithm)
  const comments = keepsComments(algorithm)
  const omit = options.omit ?? new Set<XmlNode>()
  const inclusivePrefixes = new Set(options.inclusiveNamespacePrefixes ?? [])
  const out: string[] = []

  /** Bir öğenin kendi bildirimlerini kapsama uygular. */
  const extend = (
    scope: ReadonlyMap<string, string>,
    declarations: readonly XmlNamespaceDeclaration[],
  ): Map<string, string> => {
    const next = new Map(scope)
    for (const declaration of declarations) next.set(declaration.prefix, declaration.uri)
    return next
  }

  /**
   * Bir öğe için yazılacak ad alanı bildirimlerini seçer.
   *
   * @param element - İşlenen öğe
   * @param inScope - Öğedeki geçerli tüm ad alanı bağlamı
   * @param rendered - ÇIKTIDA en yakın atada yazılmış bildirimler
   */
  const selectNamespaces = (
    element: XmlElement,
    inScope: ReadonlyMap<string, string>,
    rendered: ReadonlyMap<string, string>,
  ): RenderedNamespace[] => {
    // Aday ön ekler: kapsayıcı (inclusive) biçimde bağlamdaki HEPSİ; dışlayıcı
    // (exclusive) biçimde yalnızca gerçekten kullanılanlar artı PrefixList.
    const candidates = new Set<string>()
    if (exclusive) {
      candidates.add(element.prefix ?? '')
      for (const attribute of element.attributes) {
        if (attribute.prefix !== undefined) candidates.add(attribute.prefix)
      }
      for (const prefix of inclusivePrefixes) {
        // PrefixList'te "#default" varsayılan ad alanını gösterir.
        candidates.add(prefix === '#default' ? '' : prefix)
      }
    } else {
      for (const prefix of inScope.keys()) candidates.add(prefix)
    }

    const selected: RenderedNamespace[] = []
    for (const prefix of [...candidates].sort(compareCodePoints)) {
      // `xml` ön eki XML 1.0 tarafından sabitlenmiştir ve bildirilmesi
      // gerekmez; kaynakta AÇIKÇA bildirilmemişse yazılmaz.
      if (prefix === 'xml' && !inScope.has('xml')) continue
      const uri = inScope.get(prefix) ?? ''
      const previous = rendered.get(prefix) ?? ''
      if (uri === '') {
        // Ad alanını iptal eden bildirim (`xmlns=""`) yalnızca gerçekten bir
        // şeyi iptal ediyorsa yazılır. Aksi hâlde her ön eksiz öğeye anlamsız
        // bir `xmlns=""` eklenirdi.
        if (previous !== '') selected.push({ prefix, uri })
        continue
      }
      if (previous !== uri) selected.push({ prefix, uri })
    }
    return selected
  }

  /**
   * Yazılacak öznitelikleri sıralar.
   *
   * Sıralama, birincil anahtar ad alanı URI'si, ikincil anahtar yerel ad
   * olacak biçimdedir. Ad alanısız öznitelikler boş URI'yle en başa gelir.
   */
  const sortAttributes = (attributes: readonly XmlAttribute[]): XmlAttribute[] =>
    [...attributes].sort((a, b) => {
      const byNamespace = compareCodePoints(a.namespace ?? '', b.namespace ?? '')
      return byNamespace !== 0 ? byNamespace : compareCodePoints(a.localName, b.localName)
    })

  const renderNode = (
    node: XmlNode,
    inScope: ReadonlyMap<string, string>,
    rendered: ReadonlyMap<string, string>,
    inheritedXmlAttributes: ReadonlyMap<string, XmlAttribute>,
  ): void => {
    if (omit.has(node)) return

    if (node.kind === 'text') {
      out.push(escapeText(node.value))
      return
    }
    if (node.kind === 'comment') {
      if (comments) out.push(`<!--${escapeCommentOrInstruction(node.value)}-->`)
      return
    }
    if (node.kind === 'pi') {
      const value = escapeCommentOrInstruction(node.value)
      out.push(value === '' ? `<?${node.target}?>` : `<?${node.target} ${value}?>`)
      return
    }

    const ownScope = extend(inScope, node.namespaceDeclarations)
    const namespaces = selectNamespaces(node, ownScope, rendered)

    // Miras alınan `xml:*` öznitelikleri (xml:lang, xml:space, xml:base)
    // yalnızca KAPSAYICI biçimde ve yalnızca alt kümenin tepe öğesinde
    // yazılır — Canonical XML 1.0 §2.4. Dışlayıcı biçim bunu kasten yapmaz;
    // exclusive c14n'in var oluş nedeni tam olarak alt ağacı bağlamından
    // koparabilmektir.
    const own = new Set(
      node.attributes
        .filter((attribute) => attribute.namespace === XML_NAMESPACE)
        .map((attribute) => attribute.localName),
    )
    const inherited = [...inheritedXmlAttributes.values()].filter(
      (attribute) => !own.has(attribute.localName),
    )
    const attributes = sortAttributes([...node.attributes, ...inherited])

    const name = qualifiedName(node)
    let open = `<${name}`
    for (const namespace of namespaces) {
      const declaration = namespace.prefix === '' ? 'xmlns' : `xmlns:${namespace.prefix}`
      open += ` ${declaration}="${escapeAttributeValue(namespace.uri)}"`
    }
    for (const attribute of attributes) {
      open += ` ${qualifiedName(attribute)}="${escapeAttributeValue(attribute.value)}"`
    }
    out.push(`${open}>`)

    const nextRendered = new Map(rendered)
    for (const namespace of namespaces) nextRendered.set(namespace.prefix, namespace.uri)

    // Alt öğelere miras aktarılmaz: `xml:*` mirası yalnızca tepe öğede
    // uygulanır, çünkü aşağıdaki öğelerin ataları zaten çıktının içinde.
    const noInheritance = new Map<string, XmlAttribute>()
    for (const child of node.children) {
      renderNode(child, ownScope, nextRendered, noInheritance)
    }
    out.push(`</${name}>`)
  }

  const apex = options.subset
  if (apex === undefined) {
    const empty = new Map<string, string>()
    const noAttributes = new Map<string, XmlAttribute>()
    // Belge öğesinden ÖNCEKİ yorum/yönergeler bir `#xA` ile izlenir,
    // SONRAKİLER bir `#xA` ile önlenir — Canonical XML 1.0 §2.3.
    for (const node of document.prolog) {
      if (omit.has(node)) continue
      const before = out.length
      renderNode(node, empty, empty, noAttributes)
      if (out.length > before) out.push('\n')
    }
    renderNode(document.root, empty, empty, noAttributes)
    for (const node of document.epilog) {
      if (omit.has(node)) continue
      const before = out.length
      out.push('\n')
      renderNode(node, empty, empty, noAttributes)
      // Yorum yazılmadıysa (comments kapalı) eklediğimiz satır sonunu geri al.
      if (out.length === before + 1) out.pop()
    }
    return out.join('')
  }

  const ancestors = findAncestors(document.root, apex)
  if (ancestors === undefined) {
    throw new UnsupportedCanonicalizationError(
      'Alt küme olarak verilen öğe bu belgenin içinde değil.',
    )
  }

  let scope = new Map<string, string>()
  const xmlAttributes = new Map<string, XmlAttribute>()
  for (const ancestor of ancestors) {
    scope = extend(scope, ancestor.namespaceDeclarations)
    if (!exclusive) {
      for (const attribute of ancestor.attributes) {
        if (attribute.namespace === XML_NAMESPACE) {
          xmlAttributes.set(attribute.localName, attribute)
        }
      }
    }
  }

  renderNode(apex, scope, new Map<string, string>(), xmlAttributes)
  return out.join('')
}

/**
 * {@link canonicalize} sonucunu doğrudan UTF-8 baytları olarak verir.
 *
 * Özet alma her zaman baytlar üzerinde yapılır; dizeyi elle kodlamak
 * unutulabilecek bir adımdır.
 *
 * @param document - Kaynak belge
 * @param options - {@link CanonicalizeOptions}
 * @returns Kanonik biçimin UTF-8 kodlaması
 */
export const canonicalizeToBytes = (
  document: XmlDocument,
  options: CanonicalizeOptions = {},
): Uint8Array => utf8(canonicalize(document, options))
