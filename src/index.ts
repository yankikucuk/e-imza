/**
 * `@yankikucuk/e-imza` — XAdES elektronik imza kütüphanesi.
 *
 * Çalışma zamanı bağımlılığı yoktur. Gerekli her şey Node 20'nin kendi
 * `node:crypto` modülünden ya da bu paketin içinden gelir.
 */

/* ── XML ──────────────────────────────────────────────────────────────── */
export {
  childElements,
  childNamed,
  childrenNamed,
  getAttribute,
  getAttributeValue,
  qualifiedName,
  textContent,
  walkElements,
  XML_NAMESPACE,
  XMLNS_NAMESPACE,
  type XmlAttribute,
  type XmlComment,
  type XmlDocument,
  type XmlElement,
  type XmlNamespaceDeclaration,
  type XmlNode,
  type XmlProcessingInstruction,
  type XmlText,
} from './xml/node.js'

export { parseXml, type ParseOptions } from './xml/parse.js'

/* ── Kanonikleştirme ──────────────────────────────────────────────────── */
export {
  c14nAlgorithmFromUri,
  C14N_URI,
  canonicalize,
  canonicalizeToBytes,
  type C14nAlgorithm,
  type CanonicalizeOptions,
} from './c14n/canonicalize.js'

/* ── Hatalar ──────────────────────────────────────────────────────────── */
export {
  DerParseError,
  DoctypeNotAllowedError,
  EImzaError,
  Pkcs12Error,
  SigningError,
  UnboundPrefixError,
  UnsupportedCanonicalizationError,
  VerificationError,
  XmlLimitExceededError,
  XmlSyntaxError,
} from './core/errors.js'

/* ── Bayt yardımcıları ────────────────────────────────────────────────── */
export {
  concat,
  fromBase64,
  fromHex,
  fromUtf8,
  timingSafeEqual,
  toBase64,
  toHex,
  utf8,
  wrapBase64,
} from './core/bytes.js'
