import { createHash } from 'node:crypto'

import { C14N_URI, type C14nAlgorithm } from '../c14n/canonicalize.js'
import { toBase64, wrapBase64 } from '../core/bytes.js'
import { readCertificate } from '../pki/certificate.js'
import type { XmlElement, XmlNode } from '../xml/node.js'

import {
  COMMITMENT_OID,
  DIGEST_NODE_NAME,
  FILTER2_NAMESPACE,
  FILTER2_SUBTRACT_SIGNATURES,
  DIGEST_URI,
  Namespace,
  Prefix,
  SIGNATURE_URI,
  Transform,
  type CommitmentType,
  type DigestAlgorithm,
  type SignatureAlgorithm,
} from './constants.js'
import { attribute, ds, dsText, element, xades, xadesText } from './element.js'

/** İmzanın atıldığı yer — `xades:SignatureProductionPlace`. */
export interface ProductionPlace {
  readonly city?: string
  readonly stateOrProvince?: string
  readonly postalCode?: string
  readonly country?: string
}

/**
 * İmza politikası — XAdES-EPES.
 *
 * Özet, politika BELGESİNİN özetidir; kütüphane onu uyduramaz çünkü belgeyi
 * görmez. Bu yüzden çağıran vermek zorundadır. Uyduran bir uygulama, yapısal
 * olarak geçerli ama anlamsız bir EPES imzası üretir — doğrulayıcı özeti
 * kontrol ettiğinde reddeder.
 *
 * Politikayı adıyla anmak yetiyorsa `'implied'` kullanın; o zaman
 * `xades:SignaturePolicyImplied` yazılır ve özet gerekmez.
 */
export interface SignaturePolicy {
  /** Politika nesne tanımlayıcısı (ör. {@link TR_POLICY_OID}.P3). */
  readonly oid: string
  /** Politika belgesinin özeti. */
  readonly digest: {
    readonly algorithm: DigestAlgorithm
    readonly value: Uint8Array
  }
  /** Politika belgesinin adresi. */
  readonly uri?: string
  /** İnsan tarafından okunabilir açıklama. */
  readonly description?: string
}

/** İmzalayanın beyan ettiği rol. */
export interface SignerRole {
  readonly claimed: readonly string[]
}

/** İmza yapısındaki öğelere verilen kimlikler. */
export interface SignatureIds {
  readonly signature: string
  readonly signedInfo: string
  readonly signatureValue: string
  readonly keyInfo: string
  readonly object: string
  readonly signedProperties: string
  readonly documentReference: string
}

/**
 * Kimlikleri tek bir kökten türetir.
 *
 * `ds:SignatureValue` de kimlik alır. Bu bir ayrıntı gibi görünür ama
 * XAdES-T'nin ön koşuludur: zaman damgası tam olarak `SignatureValue`
 * öğesine referans verir. `xadesjs#142` ve `#143` bu kimliği verememekten
 * açılmıştı — kimlik yoksa imza T seviyesine hiç yükseltilemez.
 *
 * @param root - Kök kimlik (ör. `Signature-1`)
 * @returns Türetilmiş kimlikler
 */
export const deriveIds = (root: string): SignatureIds => ({
  signature: root,
  signedInfo: `${root}-SignedInfo`,
  signatureValue: `${root}-SignatureValue`,
  keyInfo: `${root}-KeyInfo`,
  object: `${root}-Object`,
  signedProperties: `${root}-SignedProperties`,
  documentReference: `${root}-Reference-Document`,
})

/** Özet alır. */
export const digest = (algorithm: DigestAlgorithm, data: Uint8Array): Uint8Array =>
  new Uint8Array(createHash(DIGEST_NODE_NAME[algorithm]).update(data).digest())

/**
 * `xsd:dateTime` biçiminde zaman üretir.
 *
 * Salise kısmı atılır. Şema onu kabul eder, ama sahadaki bazı doğrulayıcılar
 * `2026-09-07T10:00:00.000Z` biçimini reddediyor ve saliseyi yazmanın imza
 * açısından hiçbir faydası yok.
 */
export const formatSigningTime = (when: Date): string =>
  when.toISOString().replace(/\.\d{3}Z$/, 'Z')

/** {@link buildSignedProperties} girdisi. */
export interface SignedPropertiesInput {
  readonly ids: SignatureIds
  /** İmzalayan sertifika (DER). */
  readonly certificate: Uint8Array
  /** `xades:CertDigest` için özet algoritması. */
  readonly digestAlgorithm: DigestAlgorithm
  /** İmza zamanı; `null` verilirse öğe hiç yazılmaz. */
  readonly signingTime: Date | null
  readonly policy?: SignaturePolicy | 'implied'
  readonly productionPlace?: ProductionPlace
  readonly signerRole?: SignerRole
  readonly commitmentType?: CommitmentType
}

/**
 * `xades:SignedProperties` öğesini kurar.
 *
 * Öğe sırası XAdES şemasının `xsd:sequence` tanımına göredir ve isteğe bağlı
 * alanların atlanması sırayı bozmaz. Sıra yanlışsa belge şema doğrulamasından
 * geçmez; imza kriptografik olarak doğru olsa bile reddedilir.
 *
 * @param input - {@link SignedPropertiesInput}
 * @returns `xades:SignedProperties` öğesi
 */
export const buildSignedProperties = (input: SignedPropertiesInput): XmlElement => {
  const certificate = readCertificate(input.certificate)
  const certificateDigest = digest(input.digestAlgorithm, input.certificate)

  const signatureProperties = xades('SignedSignatureProperties', [
    input.signingTime === null
      ? undefined
      : xadesText('SigningTime', formatSigningTime(input.signingTime)),

    xades('SigningCertificate', [
      xades('Cert', [
        xades('CertDigest', [
          ds('DigestMethod', [], [attribute('Algorithm', DIGEST_URI[input.digestAlgorithm])]),
          dsText('DigestValue', toBase64(certificateDigest)),
        ]),
        xades('IssuerSerial', [
          dsText('X509IssuerName', certificate.issuerName),
          // ONDALIK. `xadesjs#52`: onaltılık yazılan seri numarasını dış
          // doğrulayıcılar reddediyordu.
          dsText('X509SerialNumber', certificate.serialNumber.toString(10)),
        ]),
      ]),
    ]),

    input.policy === undefined ? undefined : buildPolicyIdentifier(input.policy),

    input.productionPlace === undefined
      ? undefined
      : xades('SignatureProductionPlace', [
          input.productionPlace.city === undefined
            ? undefined
            : xadesText('City', input.productionPlace.city),
          input.productionPlace.stateOrProvince === undefined
            ? undefined
            : xadesText('StateOrProvince', input.productionPlace.stateOrProvince),
          input.productionPlace.postalCode === undefined
            ? undefined
            : xadesText('PostalCode', input.productionPlace.postalCode),
          input.productionPlace.country === undefined
            ? undefined
            : xadesText('CountryName', input.productionPlace.country),
        ]),

    input.signerRole === undefined
      ? undefined
      : xades('SignerRole', [
          xades(
            'ClaimedRoles',
            input.signerRole.claimed.map((role) => xadesText('ClaimedRole', role)),
          ),
        ]),
  ])

  const dataObjectProperties =
    input.commitmentType === undefined
      ? undefined
      : xades('SignedDataObjectProperties', [
          xades('CommitmentTypeIndication', [
            xades('CommitmentTypeId', [
              xadesText('Identifier', `urn:oid:${COMMITMENT_OID[input.commitmentType]}`),
            ]),
            xades('AllSignedDataObjects'),
          ]),
        ])

  return xades(
    'SignedProperties',
    [signatureProperties, dataObjectProperties],
    [attribute('Id', input.ids.signedProperties)],
  )
}

/** `xades:SignaturePolicyIdentifier` — EPES. */
const buildPolicyIdentifier = (policy: SignaturePolicy | 'implied'): XmlElement => {
  if (policy === 'implied') {
    return xades('SignaturePolicyIdentifier', [xades('SignaturePolicyImplied')])
  }
  return xades('SignaturePolicyIdentifier', [
    xades('SignaturePolicyId', [
      xades('SigPolicyId', [
        xadesText('Identifier', `urn:oid:${policy.oid}`),
        policy.description === undefined ? undefined : xadesText('Description', policy.description),
      ]),
      xades('SigPolicyHash', [
        ds('DigestMethod', [], [attribute('Algorithm', DIGEST_URI[policy.digest.algorithm])]),
        dsText('DigestValue', toBase64(policy.digest.value)),
      ]),
      policy.uri === undefined
        ? undefined
        : xades('SigPolicyQualifiers', [
            xades('SigPolicyQualifier', [xadesText('SPURI', policy.uri)]),
          ]),
    ]),
  ])
}

/**
 * Tek bir dönüşüm.
 *
 * Çoğu dönüşüm yalnızca bir URI'dir; XPath Filter 2.0 ise süzgeç ifadesini
 * alt öğe olarak taşır, bu yüzden `children` gerekiyor.
 */
export interface TransformInput {
  readonly algorithm: string
  readonly children?: readonly XmlNode[]
}

/** Tek bir `ds:Reference` tanımı. */
export interface ReferenceInput {
  readonly id?: string
  readonly uri: string
  readonly type?: string
  readonly transforms: readonly TransformInput[]
  readonly digestAlgorithm: DigestAlgorithm
  readonly digestValue: Uint8Array
}

/** `ds:Reference` öğesini kurar. */
export const buildReference = (reference: ReferenceInput): XmlElement =>
  ds(
    'Reference',
    [
      // Boş `<ds:Transforms/>` yazmak şemaya göre geçerli ama gereksizdir ve
      // bazı doğrulayıcıları şaşırtır (`xml-crypto#540` aynı gözlem).
      reference.transforms.length === 0
        ? undefined
        : ds(
            'Transforms',
            reference.transforms.map((transform) =>
              ds('Transform', transform.children ?? [], [
                attribute('Algorithm', transform.algorithm),
              ]),
            ),
          ),
      ds('DigestMethod', [], [attribute('Algorithm', DIGEST_URI[reference.digestAlgorithm])]),
      dsText('DigestValue', toBase64(reference.digestValue)),
    ],
    [
      ...(reference.id === undefined ? [] : [attribute('Id', reference.id)]),
      ...(reference.type === undefined ? [] : [attribute('Type', reference.type)]),
      attribute('URI', reference.uri),
    ],
  )

/** {@link buildSignedInfo} girdisi. */
export interface SignedInfoInput {
  readonly ids: SignatureIds
  readonly canonicalization: C14nAlgorithm
  readonly signatureAlgorithm: SignatureAlgorithm
  readonly references: readonly ReferenceInput[]
}

/** `ds:SignedInfo` öğesini kurar. */
export const buildSignedInfo = (input: SignedInfoInput): XmlElement =>
  ds(
    'SignedInfo',
    [
      ds('CanonicalizationMethod', [], [attribute('Algorithm', C14N_URI[input.canonicalization])]),
      ds('SignatureMethod', [], [attribute('Algorithm', SIGNATURE_URI[input.signatureAlgorithm])]),
      ...input.references.map((reference) => buildReference(reference)),
    ],
    [attribute('Id', input.ids.signedInfo)],
  )

/**
 * `ds:KeyInfo` öğesini kurar.
 *
 * Zincir isteğe bağlıdır ama varsayılan olarak yazılır: doğrulayan taraf
 * ara sertifikaları başka bir yerden bulmak zorunda kalmasın. Kapta zincir
 * yoksa yalnızca uç sertifika yazılır.
 */
export const buildKeyInfo = (
  ids: SignatureIds,
  certificate: Uint8Array,
  chain: readonly Uint8Array[],
): XmlElement =>
  ds(
    'KeyInfo',
    [
      ds('X509Data', [
        ...[certificate, ...chain].map((der) =>
          // 64 karakterlik satırlar. XMLDSig satır sonu istemez; kanonik
          // biçim metni olduğu gibi özetler, dolayısıyla sarma imzayı
          // etkilemez — ama `xadesjs#64`'te olduğu gibi belirli satır
          // genişliği bekleyen doğrulayıcılar var ve okunabilirlik bedava.
          dsText('X509Certificate', wrapBase64(toBase64(der))),
        ),
      ]),
    ],
    [attribute('Id', ids.keyInfo)],
  )

/** {@link buildSignature} girdisi. */
export interface SignatureInput {
  readonly ids: SignatureIds
  readonly signedInfo: XmlElement
  readonly signatureValue: string
  readonly certificate: Uint8Array
  readonly chain: readonly Uint8Array[]
  readonly signedProperties: XmlElement
}

/**
 * Tam `ds:Signature` öğesini kurar.
 *
 * Ad alanı bildirimleri iki yere konur: `ds:` imzanın kökünde, `xades:` ise
 * `xades:QualifyingProperties` üzerinde. İkincisi kasten yerelleştirildi —
 * dışlayıcı kanonikleştirmede `SignedProperties` alt kümesi tek başına
 * özetlenir ve `xades:` bildirimini kendi içinde bulması gerekir.
 *
 * @param input - {@link SignatureInput}
 * @returns `ds:Signature` öğesi
 */
export const buildSignature = (input: SignatureInput): XmlElement =>
  ds(
    'Signature',
    [
      input.signedInfo,
      dsText('SignatureValue', input.signatureValue, [attribute('Id', input.ids.signatureValue)]),
      buildKeyInfo(input.ids, input.certificate, input.chain),
      ds(
        'Object',
        [
          xades(
            'QualifyingProperties',
            [input.signedProperties],
            [attribute('Target', `#${input.ids.signature}`)],
            [{ prefix: Prefix.XADES, uri: Namespace.XADES }],
          ),
        ],
        [attribute('Id', input.ids.object)],
      ),
    ],
    [attribute('Id', input.ids.signature)],
    [{ prefix: Prefix.SIGNATURE, uri: Namespace.SIGNATURE }],
  )

/** Sarmalanmış (`enveloped`) belge referansının dönüşüm listesi. */
export const envelopedTransforms = (canonicalization: C14nAlgorithm): readonly TransformInput[] => [
  { algorithm: Transform.ENVELOPED_SIGNATURE },
  { algorithm: C14N_URI[canonicalization] },
]

/**
 * Paralel imza için dönüşüm listesi.
 *
 * `enveloped-signature` yerine XPath Filter 2.0 ile **bütün** imzalar
 * çıkarılır. Aradaki fark paralel imzanın tamamıdır:
 *
 * `enveloped-signature`, tanımı gereği yalnızca referansı İÇEREN imzayı
 * çıkarır. Doğru davranış budur — ama sonucu şudur: belgeye ikinci bir
 * imza eklendiğinde, birinci imzanın kapsadığı içerik değişir ve birinci
 * imza geçersiz olur. `xadesjs#87` bunu "enveloped dönüşümü tek imza
 * siliyor" diye bildirmişti; dönüşümü düzeltmek sorunu çözmez, çünkü
 * sorun dönüşümde değil referans modelindedir.
 *
 * Bütün imzalar kapsam dışında bırakılınca her imzacı aynı içeriği imzalar
 * ve imzalar birbirinden bağımsız olur — sırayla ya da ayrı ayrı
 * atılabilirler, biri silinse diğerleri geçerli kalır.
 */
export const parallelTransforms = (canonicalization: C14nAlgorithm): readonly TransformInput[] => [
  {
    algorithm: Transform.XPATH_FILTER2,
    children: [
      element(
        FILTER2_NAMESPACE,
        'dsig-xpath',
        'XPath',
        [{ kind: 'text', value: FILTER2_SUBTRACT_SIGNATURES }],
        [attribute('Filter', 'subtract')],
        [
          { prefix: 'dsig-xpath', uri: FILTER2_NAMESPACE },
          { prefix: Prefix.SIGNATURE, uri: Namespace.SIGNATURE },
        ],
      ),
    ],
  },
  { algorithm: C14N_URI[canonicalization] },
]
