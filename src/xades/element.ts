import type { XmlAttribute, XmlElement, XmlNamespaceDeclaration, XmlNode } from '../xml/node.js'

import { Namespace, Prefix } from './constants.js'

/**
 * İmza yapılarını bellekte kurmak için küçük yardımcılar.
 *
 * İmza öğeleri belgeden okunmaz, programla üretilir; bu yüzden ön ek ve ad
 * alanı bilgisini elle taşımak gerekir. Yardımcılar bunu tek yerde toplar,
 * böylece `xades:` yazılması gereken bir yere `ds:` yazılması mümkün olmaz.
 */

/** Öznitelik kısayolu — ad alanısız öznitelikler (XMLDSig'de hepsi öyle). */
export const attribute = (localName: string, value: string): XmlAttribute => ({
  namespace: undefined,
  prefix: undefined,
  localName,
  value,
})

/** Genel öğe kurucusu. */
export const element = (
  namespace: string,
  prefix: string,
  localName: string,
  children: readonly (XmlNode | undefined)[] = [],
  attributes: readonly XmlAttribute[] = [],
  namespaceDeclarations: readonly XmlNamespaceDeclaration[] = [],
): XmlElement => ({
  kind: 'element',
  namespace,
  prefix,
  localName,
  namespaceDeclarations,
  attributes,
  children: children.filter((child): child is XmlNode => child !== undefined),
})

/** `ds:` ad alanında öğe. */
export const ds = (
  localName: string,
  children: readonly (XmlNode | undefined)[] = [],
  attributes: readonly XmlAttribute[] = [],
  namespaceDeclarations: readonly XmlNamespaceDeclaration[] = [],
): XmlElement =>
  element(
    Namespace.SIGNATURE,
    Prefix.SIGNATURE,
    localName,
    children,
    attributes,
    namespaceDeclarations,
  )

/** Metin içerikli `ds:` öğesi. */
export const dsText = (
  localName: string,
  value: string,
  attributes: readonly XmlAttribute[] = [],
): XmlElement => ds(localName, [{ kind: 'text', value }], attributes)

/** `xades:` ad alanında öğe. */
export const xades = (
  localName: string,
  children: readonly (XmlNode | undefined)[] = [],
  attributes: readonly XmlAttribute[] = [],
  namespaceDeclarations: readonly XmlNamespaceDeclaration[] = [],
): XmlElement =>
  element(Namespace.XADES, Prefix.XADES, localName, children, attributes, namespaceDeclarations)

/** `xades141:` ad alanında öğe — arşiv zaman damgası için. */
export const xades141 = (
  localName: string,
  children: readonly (XmlNode | undefined)[] = [],
  attributes: readonly XmlAttribute[] = [],
  namespaceDeclarations: readonly XmlNamespaceDeclaration[] = [],
): XmlElement =>
  element(
    Namespace.XADES_141,
    Prefix.XADES_141,
    localName,
    children,
    attributes,
    namespaceDeclarations,
  )

/** Metin içerikli `xades:` öğesi. */
export const xadesText = (
  localName: string,
  value: string,
  attributes: readonly XmlAttribute[] = [],
): XmlElement => xades(localName, [{ kind: 'text', value }], attributes)
