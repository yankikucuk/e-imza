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

/* ── ASN.1 / DER ──────────────────────────────────────────────────────── */
export {
  asBitString,
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asSet,
  asString,
  asTime,
  decodeDer,
  decodeDerAt,
  DerTag,
  type DerNode,
  type DerTagClass,
} from './asn1/der.js'

/* ── Anahtar malzemesi ────────────────────────────────────────────────── */
export { loadPkcs12, type LoadPkcs12Options, type Pkcs12Bundle } from './pki/pkcs12.js'

/* ── İmzalama ─────────────────────────────────────────────────────────── */
export {
  complete,
  prepare,
  sign,
  signWithKey,
  type PendingSignature,
  type SignatureOptions,
  type SignaturePlacement,
  type SignerInput,
  type SignOptions,
} from './sign.js'

/* ── Seviye yükseltme (XAdES-T) ────────────────────────────────────────── */
export {
  archiveTimestampRequest,
  timestampRequest,
  upgrade,
  type TimestampRequestInput,
  type TimestampTarget,
  type UpgradeOptions,
  type UpgradeToArchive,
  type UpgradeToLongTerm,
  type UpgradeToTimestamp,
} from './upgrade.js'

/* ── Zaman damgası (RFC 3161) ─────────────────────────────────────────── */
export {
  buildTimestampRequest,
  parseTimestampResponse,
  parseTstInfo,
  verifyTimestampToken,
  type TimestampRequestOptions,
  type TimestampVerification,
  type TstInfo,
  type VerifyTimestampOptions,
} from './pki/tsp.js'

/* ── İptal denetimi (OCSP, RFC 6960) ──────────────────────────────────── */
export {
  buildOcspRequest,
  parseOcspResponse,
  verifyOcspResponse,
  type CertificateStatus,
  type OcspRequestOptions,
  type OcspResponse,
  type OcspVerification,
  type SingleOcspResponse,
  type VerifyOcspOptions,
} from './pki/ocsp.js'

/* ── Sertifika uzantıları ─────────────────────────────────────────────── */
export {
  caIssuerUrls,
  certificateExtension,
  certificateExtensions,
  crlDistributionUrls,
  ocspResponderUrls,
} from './pki/extensions.js'

/* ── CMS (RFC 5652) ───────────────────────────────────────────────────── */
export {
  CmsOid,
  parseCmsSignedData,
  signedAttribute,
  verifyCmsSigner,
  type CmsSignedData,
  type CmsSignerInfo,
  type CmsVerification,
} from './pki/cms.js'

/* ── CAdES (ikili veri imzası) ────────────────────────────────────────── */
export {
  cadesComplete,
  cadesPrepare,
  cadesSign,
  cadesSignWithKey,
  type CadesSignatureOptions,
  type CadesSignerInput,
  type CadesSignOptions,
  type PendingCadesSignature,
} from './cades/sign.js'

export {
  cadesVerify,
  type CadesTimestampResult,
  type CadesVerification,
  type CadesVerifyOptions,
  type CadesWarning,
} from './cades/verify.js'

export {
  cadesTimestampRequest,
  cadesUpgrade,
  type CadesTimestampRequestInput,
  type CadesUpgradeOptions,
  type CadesUpgradeToLongTerm,
  type CadesUpgradeToTimestamp,
} from './cades/upgrade.js'

export {
  COMMITMENT_OID as CADES_COMMITMENT_OID,
  SignedAttribute,
  UnsignedAttribute,
  type CadesCommitmentType,
  type CadesLevel,
} from './cades/constants.js'

export type { CadesSignaturePolicy, SignerLocation } from './cades/attributes.js'

/* ── PAdES (PDF imzası) ───────────────────────────────────────────────── */
export {
  padesComplete,
  padesPrepare,
  padesSign,
  type PadesSignatureOptions,
  type PadesSignerInput,
  type PadesSignOptions,
  type PendingPadesSignature,
} from './pades/sign.js'

export {
  padesVerify,
  type PadesSignatureResult,
  type PadesVerification,
  type PadesWarning,
} from './pades/verify.js'

/* ── PDF yapısı ───────────────────────────────────────────────────────── */
export {
  catalog,
  firstPage,
  getObject,
  readPdf,
  resolve as resolvePdfObject,
  type PdfDocument,
} from './pdf/document.js'

export { dictEntry, PdfReader, type PdfObject } from './pdf/object.js'

/* ── ASiC (imzalı konteyner) ──────────────────────────────────────────── */
export {
  ASIC_MIME_TYPE,
  createAsic,
  readAsic,
  type AsicContainer,
  type AsicDataFile,
  type AsicManifestEntry,
  type AsicSignature,
  type AsicSignatureEntry,
  type AsicSignatureFormat,
  type AsicType,
  type CreateAsicOptions,
} from './asic/container.js'

/* ── ZIP ──────────────────────────────────────────────────────────────── */
export { createZip, peekFirstEntry, readZip, type ZipEntry } from './zip/archive.js'
export { crc32 } from './zip/crc32.js'

/* ── Doğrulama ────────────────────────────────────────────────────────── */
export {
  verify,
  verifyAll,
  type ReferenceResult,
  type SignatureLevel,
  type TimestampResult,
  type VerificationResult,
  type VerificationWarning,
  type VerifyOptions,
} from './verify.js'

/* ── XAdES sabitleri ve tipleri ───────────────────────────────────────── */
export {
  COMMITMENT_OID,
  DIGEST_URI,
  Namespace,
  Prefix,
  ReferenceType,
  SIGNATURE_URI,
  TR_POLICY_OID,
  Transform,
  Ubl,
  type CommitmentType,
  type DigestAlgorithm,
  type SignatureAlgorithm,
} from './xades/constants.js'

export type { ProductionPlace, SignaturePolicy, SignerRole } from './xades/signature.js'

/* ── Sertifika ────────────────────────────────────────────────────────── */
export { readCertificate, type CertificateInfo } from './pki/certificate.js'

/* ── XML düzenleme ────────────────────────────────────────────────────── */
export { findElementById } from './xml/edit.js'
export { serializeElement, serializeXml, type SerializeOptions } from './xml/serialize.js'

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
