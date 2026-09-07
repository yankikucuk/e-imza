import { escapeAttributeValue, escapeCommentOrInstruction, escapeText } from './escape.js'
import { qualifiedName, type XmlDocument, type XmlElement, type XmlNode } from './node.js'

/**
 * Düğüm ağacını XML metnine geri yazar.
 *
 * Serileştirici **gidiş-dönüş güvenlidir**: ürettiği metin yeniden
 * ayrıştırıldığında birebir aynı ağacı verir. İmza kütüphanesinde bu bir
 * incelik değil, doğruluk koşuludur.
 *
 * Kritik nokta satır başı karakteridir. Kaynakta `&#xD;` diye yazılmış bir
 * karakter, ayrıştırıldığında gerçek bir CR olur. Serileştirici onu DÜZ CR
 * olarak yazarsa, belge bir daha okunduğunda satır sonu normalizasyonu onu
 * `\n`'e çevirir — yani imzalanan belge ile doğrulanan belge farklı olur ve
 * imza tutmaz. Bu yüzden kaçırma kuralları kanonik biçimle aynıdır.
 *
 * Kanonik biçimden farkı, kaynağın YAPISINI koruması: ön ekler, ad alanı
 * bildirimlerinin yeri ve öznitelik sırası olduğu gibi kalır. Kanonik biçim
 * bunları normalleştirir; belgeyi kullanıcıya geri verirken normalleştirmek
 * ise gereksiz bir değişikliktir.
 */

/** {@link serializeXml} seçenekleri. */
export interface SerializeOptions {
  /**
   * Başa yazılacak XML bildirimi. Varsayılan
   * `<?xml version="1.0" encoding="UTF-8"?>`; `null` verilirse yazılmaz.
   */
  readonly declaration?: string | null
}

const DEFAULT_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>'

/** Tek bir düğümü yazar. */
const writeNode = (node: XmlNode, out: string[]): void => {
  if (node.kind === 'text') {
    out.push(escapeText(node.value))
    return
  }
  if (node.kind === 'comment') {
    out.push(`<!--${escapeCommentOrInstruction(node.value)}-->`)
    return
  }
  if (node.kind === 'pi') {
    const value = escapeCommentOrInstruction(node.value)
    out.push(value === '' ? `<?${node.target}?>` : `<?${node.target} ${value}?>`)
    return
  }

  const name = qualifiedName(node)
  let open = `<${name}`
  for (const declaration of node.namespaceDeclarations) {
    const attribute = declaration.prefix === '' ? 'xmlns' : `xmlns:${declaration.prefix}`
    open += ` ${attribute}="${escapeAttributeValue(declaration.uri)}"`
  }
  for (const attribute of node.attributes) {
    open += ` ${qualifiedName(attribute)}="${escapeAttributeValue(attribute.value)}"`
  }

  // Boş öğe kısa biçimde yazılır. Kanonik biçim bunu açar; serileştirme ise
  // kaynağın okunabilirliğini korur ve kanonik özeti etkilemez.
  if (node.children.length === 0) {
    out.push(`${open}/>`)
    return
  }
  out.push(`${open}>`)
  for (const child of node.children) writeNode(child, out)
  out.push(`</${name}>`)
}

/**
 * Belgeyi XML metnine çevirir.
 *
 * @param document - Yazılacak belge
 * @param options - {@link SerializeOptions}
 * @returns XML metni
 *
 * @example
 * ```ts
 * const doc = parseXml(kaynak)
 * serializeXml(doc) // kaynakla aynı ağacı veren metin
 * ```
 */
export const serializeXml = (document: XmlDocument, options: SerializeOptions = {}): string => {
  const out: string[] = []
  const declaration = options.declaration === undefined ? DEFAULT_DECLARATION : options.declaration
  if (declaration !== null) out.push(declaration, '\n')
  for (const node of document.prolog) {
    writeNode(node, out)
    out.push('\n')
  }
  writeNode(document.root, out)
  for (const node of document.epilog) {
    out.push('\n')
    writeNode(node, out)
  }
  return out.join('')
}

/**
 * Tek bir öğeyi metne çevirir (belge bildirimi olmadan).
 *
 * @param element - Yazılacak öğe
 * @returns XML parçası
 */
export const serializeElement = (element: XmlElement): string => {
  const out: string[] = []
  writeNode(element, out)
  return out.join('')
}
