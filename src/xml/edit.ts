import {
  getAttributeValue,
  XML_NAMESPACE,
  type XmlDocument,
  type XmlElement,
  type XmlNode,
} from './node.js'

/**
 * Ağaç üzerinde yapısal düzenleme.
 *
 * Düğümler değiştirilemez olduğu için düzenleme, yolu yeniden kurup geri
 * kalanı paylaşmak demektir. Bunun imza kodunda somut bir faydası var:
 * imzalama sırasında belge birkaç kez yeniden kurulur (önce imza iskeleti
 * eklenir, sonra özetler, sonra imza değeri) ve her adımda ÖNCEKİ hâl
 * elde kalır. Yerinde değiştiren bir modelde, bir adım yarıda kalırsa
 * belge tanımsız bir ara durumda kalırdı.
 */

/**
 * Bir öğeyi başka bir öğeyle değiştirir.
 *
 * Karşılaştırma nesne kimliğiyle yapılır; aynı ada sahip başka bir öğe
 * yanlışlıkla değiştirilmez.
 *
 * @param document - Kaynak belge
 * @param target - Değiştirilecek öğe (belgenin içinden)
 * @param replacement - Yerine konacak öğe
 * @returns Yeni belge; hedef bulunamazsa kaynağın kendisi
 */
export const replaceElement = (
  document: XmlDocument,
  target: XmlElement,
  replacement: XmlElement,
): XmlDocument => {
  const visit = (node: XmlNode): XmlNode => {
    if (node === target) return replacement
    if (node.kind !== 'element') return node
    const children = node.children.map((child) => visit(child))
    // Hiçbir alt düğüm değişmediyse öğenin kendisi döner; böylece
    // değişmeyen dallar yeniden kurulmaz ve nesne kimliği korunur.
    const changed = children.some((child, index) => child !== node.children[index])
    return changed ? { ...node, children } : node
  }

  const root = visit(document.root)
  return root === document.root ? document : { ...document, root: root as XmlElement }
}

/**
 * Bir öğenin alt düğümlerinin sonuna ekleme yapar.
 *
 * @param document - Kaynak belge
 * @param parent - Ekleme yapılacak öğe (belgenin içinden)
 * @param children - Eklenecek düğümler
 * @returns Yeni belge
 */
export const appendChildren = (
  document: XmlDocument,
  parent: XmlElement,
  ...children: readonly XmlNode[]
): XmlDocument =>
  replaceElement(document, parent, { ...parent, children: [...parent.children, ...children] })

/**
 * XMLDSig'in `URI="#kimlik"` başvurusunu çözer.
 *
 * Şema ya da DTD olmadan hangi özniteliğin kimlik olduğu bilinemez;
 * XMLDSig uygulamaları geleneksel olarak `Id`, `ID` ve `id` adlarına
 * bakar, `xml:id` ise standarttır. Dördü de denenir.
 *
 * Aynı kimliği taşıyan birden çok öğe varsa `undefined` döner. Bu bilinçli:
 * belirsiz bir kimlik, imzanın hangi içeriği kapsadığını belirsizleştirir ve
 * "ilkini al" demek, saldırganın araya kendi öğesini koymasına izin verir
 * (imza sarma — signature wrapping — saldırısının klasik biçimi).
 *
 * @param document - Aranacak belge
 * @param id - Kimlik değeri (baştaki `#` olmadan)
 * @returns Tek eşleşme varsa o öğe, yoksa ya da birden çoksa `undefined`
 */
export const findElementById = (document: XmlDocument, id: string): XmlElement | undefined => {
  const matches: XmlElement[] = []
  const visit = (element: XmlElement): void => {
    if (
      getAttributeValue(element, 'Id') === id ||
      getAttributeValue(element, 'ID') === id ||
      getAttributeValue(element, 'id') === id ||
      getAttributeValue(element, 'id', XML_NAMESPACE) === id
    ) {
      matches.push(element)
    }
    for (const child of element.children) {
      if (child.kind === 'element') visit(child)
    }
  }
  visit(document.root)
  return matches.length === 1 ? matches[0] : undefined
}
