import type { KeyObject } from 'node:crypto'

import type { CadesSignaturePolicy, SignerLocation } from '../cades/attributes.js'
import type { CadesCommitmentType } from '../cades/constants.js'
import { cadesComplete, cadesPrepare, cadesSignWithKey } from '../cades/sign.js'
import type { CmsDigest } from '../pki/cms-build.js'

import { DEFAULT_SIGNATURE_SPACE, pdfDate, pdfText, placeSignatureField } from './placement.js'

/**
 * PAdES — PDF imzası (ETSI EN 319 142).
 *
 * PDF'e gömülen şey **ayrık bir CAdES imzasıdır**; bu yüzden PAdES kendi
 * kriptografisini getirmiyor, {@link ../cades/sign.js | CAdES katmanının}
 * üstüne oturuyor. Getirdiği şey PDF'e özgü olan kısım: artımlı güncelleme,
 * imza sözlüğü ve `/ByteRange` hesabı.
 *
 * ## Özgün baytlara dokunulmaz
 *
 * İmza dosyanın SONUNA eklenir, eski çapraz başvuru `/Prev` ile zincire
 * bağlanır. Daha önce atılmış imzalar bu yüzden bozulmaz — ve aynı belgeye
 * üst üste imza atılabilmesinin nedeni budur.
 */

/** İmzalayanın kimlik malzemesi. */
export interface PadesSignerInput {
  readonly certificate: Uint8Array
  readonly chain?: readonly Uint8Array[]
}

/** {@link padesSign} ve {@link padesPrepare} için ortak seçenekler. */
export interface PadesSignatureOptions {
  /** İmzalanacak PDF. */
  readonly pdf: Uint8Array
  readonly signer: PadesSignerInput
  /** Özet algoritması; varsayılan `sha256`. */
  readonly digest?: CmsDigest
  /** İmza zamanı; `null` verilirse `/M` ve `signingTime` yazılmaz. */
  readonly signingTime?: Date | null
  /** İmza gerekçesi — `/Reason`. */
  readonly reason?: string
  /** İmzanın atıldığı yer — `/Location`. */
  readonly location?: string
  /** İmzalayanın adı — `/Name`. */
  readonly name?: string
  /** İletişim bilgisi — `/ContactInfo`. */
  readonly contactInfo?: string
  readonly policy?: CadesSignaturePolicy | 'implied'
  readonly commitmentType?: CadesCommitmentType
  readonly signerLocation?: SignerLocation
  /**
   * İmza için ayrılacak yer (onaltılık karakter sayısı). Varsayılan 16384,
   * yani 8 KB imza.
   *
   * PDF'te imzanın boyutu **imza atılmadan önce** ayrılmak zorunda: yer
   * ayrılmadan `/ByteRange` hesaplanamaz, `/ByteRange` olmadan imzalanacak
   * baytlar belli olmaz. Zincir ve zaman damgası gömülecekse artırın;
   * ayrılan yer imzadan büyükse kalanı sıfırla doldurulur.
   */
  readonly signatureSpace?: number
}

/** {@link padesSign} seçenekleri. */
export interface PadesSignOptions extends PadesSignatureOptions {
  readonly privateKey: KeyObject
}

/** Dışarıda imzalanmayı bekleyen PDF imzası. */
export interface PendingPadesSignature {
  /** İmzalanacak baytlar — `/ByteRange`ın gösterdiği iki dilimin birleşimi. */
  readonly dataToSign: Uint8Array
  /** {@link dataToSign} baytlarının özeti. */
  readonly digest: Uint8Array
  /** RSA PKCS#1 v1.5 için DER `DigestInfo`; EC anahtarlarda `undefined`. */
  readonly digestInfo?: Uint8Array
  readonly digestAlgorithm: CmsDigest
  readonly keyKind: 'rsa' | 'ec'
  /** @internal */
  readonly finish: (cms: Uint8Array) => Uint8Array
  /** @internal */
  readonly completeCades: (signature: Uint8Array) => Uint8Array
}

/**
 * PDF'i PAdES ile imzalar.
 *
 * @param options - {@link PadesSignOptions}
 * @returns İmzalanmış PDF
 *
 * @example
 * ```ts
 * const { privateKey, certificate, chain } = loadPkcs12(p12, sifre)
 * const imzali = padesSign({
 *   pdf: readFileSync('belge.pdf'),
 *   signer: { certificate, chain },
 *   privateKey,
 *   reason: 'Onay',
 *   location: 'İstanbul',
 * })
 * ```
 */
export const padesSign = (options: PadesSignOptions): Uint8Array => {
  const pending = padesPrepare(options)
  const cms = pending.completeCades(cadesSignWithKeyFor(pending, options.privateKey))
  return pending.finish(cms)
}

/** Bekleyen imzayı yerel anahtarla imzalar. */
const cadesSignWithKeyFor = (pending: PendingPadesSignature, privateKey: KeyObject): Uint8Array =>
  cadesSignWithKey(
    {
      dataToSign: pending.dataToSign,
      digest: pending.digest,
      digestAlgorithm: pending.digestAlgorithm,
      keyKind: pending.keyKind,
      build: () => new Uint8Array(0),
      ...(pending.digestInfo === undefined ? {} : { digestInfo: pending.digestInfo }),
    },
    privateKey,
  )

/**
 * İmzayı, imza değeri dışında tamamen hazırlar.
 *
 * @param options - {@link PadesSignatureOptions}
 * @returns İmzalanmayı bekleyen imza
 */
export const padesPrepare = (options: PadesSignatureOptions): PendingPadesSignature => {
  const signingTime = options.signingTime === undefined ? new Date() : options.signingTime

  // İmza sözlüğünün PAdES'e özgü girdileri. `/ByteRange` ve `/Contents`
  // yer tutucularını yerleştirici yazıyor.
  const dictionary = [
    '/Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached',
    ...(signingTime === null ? [] : [`/M ${pdfDate(signingTime)}`]),
    ...(options.reason === undefined ? [] : [`/Reason ${pdfText(options.reason)}`]),
    ...(options.location === undefined ? [] : [`/Location ${pdfText(options.location)}`]),
    ...(options.name === undefined ? [] : [`/Name ${pdfText(options.name)}`]),
    ...(options.contactInfo === undefined ? [] : [`/ContactInfo ${pdfText(options.contactInfo)}`]),
  ].join('\n')

  const placed = placeSignatureField({
    pdf: options.pdf,
    space: options.signatureSpace ?? DEFAULT_SIGNATURE_SPACE,
    dictionary,
    fieldPrefix: 'Imza',
  })

  // Ayrık CAdES imzası — `/SubFilter /ETSI.CAdES.detached` tam olarak bunu
  // söylüyor.
  const cades = cadesPrepare({
    data: placed.signedBytes,
    signer: options.signer,
    attached: false,
    digest: options.digest ?? 'sha256',
    signingTime,
    ...(options.policy === undefined ? {} : { policy: options.policy }),
    ...(options.commitmentType === undefined ? {} : { commitmentType: options.commitmentType }),
    ...(options.signerLocation === undefined ? {} : { signerLocation: options.signerLocation }),
  })

  return {
    dataToSign: cades.dataToSign,
    digest: cades.digest,
    ...(cades.digestInfo === undefined ? {} : { digestInfo: cades.digestInfo }),
    digestAlgorithm: cades.digestAlgorithm,
    keyKind: cades.keyKind,
    completeCades: (signature: Uint8Array): Uint8Array => cadesComplete(cades, signature),
    finish: placed.finish,
  }
}

/**
 * Dışarıda üretilmiş imza değerini yerine koyar.
 *
 * @param pending - {@link padesPrepare} çıktısı
 * @param signature - Ham imza baytları (CAdES kuralı: ECDSA'da DER)
 * @returns İmzalanmış PDF
 */
export const padesComplete = (pending: PendingPadesSignature, signature: Uint8Array): Uint8Array =>
  pending.finish(pending.completeCades(signature))
