/**
 * CAdES nesne tanımlayıcıları — ETSI TS 101 733 / EN 319 122 ve RFC 5035.
 *
 * Tek kaynak: paketteki her yer buradan okur.
 */

/** İmzalanmış öznitelik OID'leri. */
export const SignedAttribute = {
  /** PKCS#9 — sarmalanan içeriğin türü. Zorunlu. */
  CONTENT_TYPE: '1.2.840.113549.1.9.3',
  /** PKCS#9 — sarmalanan içeriğin özeti. Zorunlu. */
  MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
  /** PKCS#9 — imza zamanı. */
  SIGNING_TIME: '1.2.840.113549.1.9.5',
  /**
   * RFC 5035 — imzalayan sertifikayı imzaya bağlar. **CAdES-BES'in
   * tanımlayıcı özniteliği budur**; olmadan imza düz bir CMS imzasıdır.
   */
  SIGNING_CERTIFICATE_V2: '1.2.840.113549.1.9.16.2.47',
  /** RFC 5035 — SHA-1 çağının karşılığı; okunur, YAZILMAZ. */
  SIGNING_CERTIFICATE_V1: '1.2.840.113549.1.9.16.2.12',
  /** ETSI — imza politikası; varlığı imzayı EPES yapar. */
  SIGNATURE_POLICY_ID: '1.2.840.113549.1.9.16.2.15',
  /** ETSI — taahhüt türü. */
  COMMITMENT_TYPE: '1.2.840.113549.1.9.16.2.16',
  /** ETSI — imzalayanın yeri. */
  SIGNER_LOCATION: '1.2.840.113549.1.9.16.2.17',
} as const

/** İmzalanmamış öznitelik OID'leri. */
export const UnsignedAttribute = {
  /** ETSI — imza zaman damgası; T seviyesi. */
  SIGNATURE_TIMESTAMP: '1.2.840.113549.1.9.16.2.14',
  /** ETSI — sertifika zinciri; LT seviyesi. */
  CERTIFICATE_VALUES: '1.2.840.113549.1.9.16.2.23',
  /** ETSI — iptal verisi; LT seviyesi. */
  REVOCATION_VALUES: '1.2.840.113549.1.9.16.2.24',
  /** ETSI — arşiv zaman damgası v3; LTA seviyesi. */
  ARCHIVE_TIMESTAMP_V3: '0.4.0.1733.2.4',
  /** ETSI — arşiv zaman damgası v2; okunur. */
  ARCHIVE_TIMESTAMP_V2: '1.2.840.113549.1.9.16.2.48',
} as const

/** Taahhüt türü. XAdES'teki karşılıklarıyla aynı OID'leri kullanır. */
export type CadesCommitmentType =
  | 'proof-of-origin'
  | 'proof-of-receipt'
  | 'proof-of-delivery'
  | 'proof-of-sender'
  | 'proof-of-approval'
  | 'proof-of-creation'

/** Taahhüt türü → OID. */
export const COMMITMENT_OID: Readonly<Record<CadesCommitmentType, string>> = {
  'proof-of-origin': '1.2.840.113549.1.9.16.6.1',
  'proof-of-receipt': '1.2.840.113549.1.9.16.6.2',
  'proof-of-delivery': '1.2.840.113549.1.9.16.6.3',
  'proof-of-sender': '1.2.840.113549.1.9.16.6.4',
  'proof-of-approval': '1.2.840.113549.1.9.16.6.5',
  'proof-of-creation': '1.2.840.113549.1.9.16.6.6',
}

/** CAdES imza seviyeleri. */
export type CadesLevel = 'CMS' | 'BES' | 'EPES' | 'T' | 'LT' | 'LTA'
