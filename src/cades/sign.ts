import { sign as nodeSign, X509Certificate, type KeyObject } from 'node:crypto'

import { derNull, derOctetString, derOid, derSequence } from '../asn1/der.js'
import { SigningError } from '../core/errors.js'
import {
  buildSignedData,
  cmsDigest,
  encodeSignedAttributes,
  type CmsDigest,
} from '../pki/cms-build.js'
import { CmsOid } from '../pki/cms.js'

import {
  commitmentTypeAttribute,
  contentTypeAttribute,
  messageDigestAttribute,
  signaturePolicyAttribute,
  signerLocationAttribute,
  signingCertificateAttribute,
  signingTimeAttribute,
  type CadesSignaturePolicy,
  type SignerLocation,
} from './attributes.js'
import type { CadesCommitmentType } from './constants.js'

/**
 * CAdES imzalama — ETSI TS 101 733 / EN 319 122.
 *
 * XAdES'in ikili veri karşılığı. Aynı imza politikaları, aynı taahhüt
 * türleri, aynı seviye merdiveni; farkı taşıyıcı: XML yerine CMS.
 *
 * XAdES ile aynı ayrık imzalama deseni burada da var —
 * {@link cadesPrepare} / {@link cadesComplete} — çünkü akıllı kart ve HSM
 * senaryosu belge biçiminden bağımsız.
 */

/** İmzalayanın kimlik malzemesi. */
export interface CadesSignerInput {
  /** İmzalayan sertifika (DER). */
  readonly certificate: Uint8Array
  /** Yapıya gömülecek ara ve kök sertifikalar (DER). */
  readonly chain?: readonly Uint8Array[]
}

/** {@link cadesSign} ve {@link cadesPrepare} için ortak seçenekler. */
export interface CadesSignatureOptions {
  /** İmzalanacak veri. */
  readonly data: Uint8Array
  readonly signer: CadesSignerInput
  /**
   * Veri imzaya gömülsün mü. Varsayılan `true`.
   *
   * `false` verildiğinde ayrık (detached) imza üretilir: yapı yalnızca
   * özeti taşır, veri dışarıda kalır. Büyük dosyalarda tercih edilir ama
   * doğrulayan tarafın veriyi ayrıca elde etmesi gerekir.
   */
  readonly attached?: boolean
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digest?: CmsDigest
  /** Sarmalanan içeriğin türü; varsayılan `id-data`. */
  readonly contentType?: string
  /** İmza zamanı; `null` verilirse `signingTime` özniteliği yazılmaz. */
  readonly signingTime?: Date | null
  /** İmza politikası — verilirse imza EPES seviyesinde olur. */
  readonly policy?: CadesSignaturePolicy | 'implied'
  readonly commitmentType?: CadesCommitmentType
  readonly signerLocation?: SignerLocation
}

/** {@link cadesSign} seçenekleri. */
export interface CadesSignOptions extends CadesSignatureOptions {
  readonly privateKey: KeyObject
}

/**
 * Dışarıda imzalanmayı bekleyen CAdES imzası.
 *
 * XAdES'teki {@link PendingSignature} ile aynı amaç: özel anahtara
 * erişilemeyen her durum — akıllı kart, donanım güvenlik modülü, uzak
 * imza servisi.
 */
export interface PendingCadesSignature {
  /**
   * İmzalanacak baytlar — `signedAttrs`ın `SET` etiketli DER kodlaması.
   *
   * RFC 5652 §5.4 imzanın tam olarak bu kodlama üzerinde hesaplanmasını
   * şart koşar.
   */
  readonly dataToSign: Uint8Array
  /** {@link dataToSign} baytlarının özeti. */
  readonly digest: Uint8Array
  /** RSA PKCS#1 v1.5 için DER `DigestInfo`; EC anahtarlarda `undefined`. */
  readonly digestInfo?: Uint8Array
  /** Özet algoritması. */
  readonly digestAlgorithm: CmsDigest
  /** Anahtar türü. */
  readonly keyKind: 'rsa' | 'ec'
  /** @internal */
  readonly build: (signature: Uint8Array) => Uint8Array
}

/** RSA PKCS#1 v1.5 `DigestInfo` için özet OID'leri. */
const DIGEST_OID: Readonly<Record<CmsDigest, string>> = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

/**
 * Veriyi CAdES ile imzalar.
 *
 * @param options - {@link CadesSignOptions}
 * @returns CMS `ContentInfo` DER kodlaması
 *
 * @example
 * ```ts
 * const { privateKey, certificate, chain } = loadPkcs12(p12, sifre)
 * const imza = cadesSign({
 *   data: readFileSync('belge.bin'),
 *   signer: { certificate, chain },
 *   privateKey,
 *   commitmentType: 'proof-of-origin',
 * })
 * ```
 */
export const cadesSign = (options: CadesSignOptions): Uint8Array => {
  const pending = cadesPrepare(options)
  return cadesComplete(pending, cadesSignWithKey(pending, options.privateKey))
}

/**
 * İmzayı, imza değeri dışında tamamen hazırlar.
 *
 * @param options - {@link CadesSignatureOptions}
 * @returns İmzalanmayı bekleyen imza
 */
export const cadesPrepare = (options: CadesSignatureOptions): PendingCadesSignature => {
  const digestAlgorithm = options.digest ?? 'sha256'
  const contentType = options.contentType ?? CmsOid.DATA
  const attached = options.attached ?? true

  let keyKind: 'rsa' | 'ec'
  try {
    const type = new X509Certificate(Buffer.from(options.signer.certificate)).publicKey
      .asymmetricKeyType
    if (type === 'rsa' || type === 'rsa-pss') keyKind = 'rsa'
    else if (type === 'ec') keyKind = 'ec'
    else throw new SigningError(`Desteklenmeyen anahtar türü: ${type ?? 'bilinmiyor'}`)
  } catch (error) {
    if (error instanceof SigningError) throw error
    throw new SigningError(
      `Sertifika okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  // İmzalanmış öznitelikler. `contentType` ve `messageDigest` zorunlu;
  // `signingCertificateV2` ise imzayı CAdES-BES yapan öznitelik.
  const attributes: Uint8Array[] = [
    contentTypeAttribute(contentType),
    messageDigestAttribute(cmsDigest(digestAlgorithm, options.data)),
    signingCertificateAttribute(options.signer.certificate, digestAlgorithm),
  ]
  const signingTime = options.signingTime === undefined ? new Date() : options.signingTime
  if (signingTime !== null) attributes.push(signingTimeAttribute(signingTime))
  if (options.policy !== undefined) attributes.push(signaturePolicyAttribute(options.policy))
  if (options.commitmentType !== undefined) {
    attributes.push(commitmentTypeAttribute(options.commitmentType))
  }
  if (options.signerLocation !== undefined) {
    attributes.push(signerLocationAttribute(options.signerLocation))
  }

  const signedAttributes = encodeSignedAttributes(attributes)
  const dataDigest = cmsDigest(digestAlgorithm, signedAttributes)

  return {
    dataToSign: signedAttributes,
    digest: dataDigest,
    ...(keyKind === 'rsa'
      ? {
          digestInfo: derSequence(
            derSequence(derOid(DIGEST_OID[digestAlgorithm]), derNull()),
            derOctetString(dataDigest),
          ),
        }
      : {}),
    digestAlgorithm,
    keyKind,
    build: (signature: Uint8Array): Uint8Array =>
      buildSignedData({
        contentType,
        content: options.data,
        attached,
        certificate: options.signer.certificate,
        ...(options.signer.chain === undefined ? {} : { chain: options.signer.chain }),
        digest: digestAlgorithm,
        keyKind,
        signedAttributes,
        signature,
      }),
  }
}

/**
 * Dışarıda üretilmiş imza değerini yerine koyar.
 *
 * @param pending - {@link cadesPrepare} çıktısı
 * @param signature - Ham imza baytları
 * @returns CMS `ContentInfo` DER kodlaması
 *
 * @remarks
 * ECDSA imzası **DER** biçiminde beklenir — `SEQUENCE { r, s }`. Bu,
 * XAdES'in tersidir: XMLDSig ham `r‖s` ister, CMS ise DER. Aynı kartın
 * çıktısı iki biçimde de kullanılacaksa dönüştürmek çağıranın işi.
 */
export const cadesComplete = (
  pending: PendingCadesSignature,
  signature: Uint8Array,
): Uint8Array => {
  if (signature.length === 0) throw new SigningError('İmza değeri boş.')
  return pending.build(signature)
}

/**
 * Bekleyen imzayı yerel bir özel anahtarla imzalar.
 *
 * @param pending - {@link cadesPrepare} çıktısı
 * @param privateKey - Özel anahtar
 * @returns Ham imza baytları
 */
export const cadesSignWithKey = (
  pending: PendingCadesSignature,
  privateKey: KeyObject,
): Uint8Array =>
  // CMS, ECDSA imzasını DER olarak ister; Node'un varsayılanı da budur.
  // XAdES'te `ieee-p1363` gerekiyordu — fark burada bilinçli.
  new Uint8Array(nodeSign(pending.digestAlgorithm, Buffer.from(pending.dataToSign), privateKey))
