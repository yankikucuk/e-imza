/**
 * XMLDSig ve XAdES ad alanları, algoritma URI'leri ve nesne tanımlayıcıları.
 *
 * Tek kaynak: paketteki her yer bu dosyadan okur. Bir URI'nin iki yerde
 * yazılması, birinin güncellenip diğerinin unutulması demektir ve imza
 * kodunda bunun sonucu sessizce geçersiz bir imzadır.
 */

/** Ad alanı URI'leri. */
export const Namespace = {
  /** XML Signature çekirdeği. */
  SIGNATURE: 'http://www.w3.org/2000/09/xmldsig#',
  /** XAdES v1.3.2 — `SignedProperties` ve arkadaşları burada. */
  XADES: 'http://uri.etsi.org/01903/v1.3.2#',
  /** XAdES v1.4.1 — arşiv zaman damgası için. */
  XADES_141: 'http://uri.etsi.org/01903/v1.4.1#',
} as const

/** Geleneksel ön ekler. Doğrulayıcılar ön eke bakmaz ama insanlar bakar. */
export const Prefix = {
  SIGNATURE: 'ds',
  XADES: 'xades',
  XADES_141: 'xades141',
} as const

/** `ds:Reference` üzerindeki `Type` değerleri. */
export const ReferenceType = {
  SIGNED_PROPERTIES: 'http://uri.etsi.org/01903#SignedProperties',
  COUNTERSIGNED_SIGNATURE: 'http://uri.etsi.org/01903#CountersignedSignature',
} as const

/** Desteklenen özet algoritmaları. */
export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512'

/**
 * Özet algoritması → URI.
 *
 * SHA-1 kasten yok. Çakışma üretmek 2017'den beri pratikte mümkün ve GİB
 * de dâhil olmak üzere ciddi hiçbir taraf artık SHA-1 imza kabul etmiyor.
 * "Eski sistemlerle uyum" gerekçesiyle açık bırakmak, kullanıcıyı zayıf
 * bir imzaya bir seçenek kadar yakın tutmak olurdu.
 */
export const DIGEST_URI: Readonly<Record<DigestAlgorithm, string>> = {
  'SHA-256': 'http://www.w3.org/2001/04/xmlenc#sha256',
  'SHA-384': 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  'SHA-512': 'http://www.w3.org/2001/04/xmlenc#sha512',
}

/** Özet algoritması → `node:crypto` adı. */
export const DIGEST_NODE_NAME: Readonly<Record<DigestAlgorithm, string>> = {
  'SHA-256': 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
}

/** Desteklenen imza algoritmaları. */
export type SignatureAlgorithm =
  | 'RSA-SHA256'
  | 'RSA-SHA384'
  | 'RSA-SHA512'
  | 'RSA-PSS-SHA256'
  | 'RSA-PSS-SHA384'
  | 'RSA-PSS-SHA512'
  | 'ECDSA-SHA256'
  | 'ECDSA-SHA384'
  | 'ECDSA-SHA512'

/** İmza algoritması → URI. */
export const SIGNATURE_URI: Readonly<Record<SignatureAlgorithm, string>> = {
  'RSA-SHA256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'RSA-SHA384': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
  'RSA-SHA512': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'RSA-PSS-SHA256': 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1',
  'RSA-PSS-SHA384': 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1',
  'RSA-PSS-SHA512': 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1',
  'ECDSA-SHA256': 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
  'ECDSA-SHA384': 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
  'ECDSA-SHA512': 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
}

/** İmza algoritmasının kullandığı özet. */
export const SIGNATURE_DIGEST: Readonly<Record<SignatureAlgorithm, DigestAlgorithm>> = {
  'RSA-SHA256': 'SHA-256',
  'RSA-SHA384': 'SHA-384',
  'RSA-SHA512': 'SHA-512',
  'RSA-PSS-SHA256': 'SHA-256',
  'RSA-PSS-SHA384': 'SHA-384',
  'RSA-PSS-SHA512': 'SHA-512',
  'ECDSA-SHA256': 'SHA-256',
  'ECDSA-SHA384': 'SHA-384',
  'ECDSA-SHA512': 'SHA-512',
}

/** Dönüşüm URI'leri. */
export const Transform = {
  ENVELOPED_SIGNATURE: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  BASE64: 'http://www.w3.org/2000/09/xmldsig#base64',
  /** XPath Filter 2.0 — paralel imzanın ön koşulu. */
  XPATH_FILTER2: 'http://www.w3.org/2002/06/xmldsig-filter2',
} as const

/** XPath Filter 2.0'ın kendi ad alanı. */
export const FILTER2_NAMESPACE = 'http://www.w3.org/2002/06/xmldsig-filter2'

/**
 * Paralel imzada kullanılan tek süzgeç ifadesi.
 *
 * Bu paket genel bir XPath motoru içermez ve içermeye de çalışmaz: imza
 * kapsamını belirleyen bir ifadeyi yaklaşık değerlendirmek, imzanın
 * kapsamadığı bir içeriği kapsıyormuş gibi göstermek demektir. Onun yerine
 * TEK bir iyi tanımlı deyim desteklenir — "bütün imzaları çıkar" — ve
 * başka her ifade açıkça reddedilir.
 */
export const FILTER2_SUBTRACT_SIGNATURES = '//ds:Signature'

/**
 * ETSI taahhüt türü tanımlayıcıları (TS 101 903 §7.2.6).
 *
 * `proof-of-origin`, "bu belgeyi ben oluşturdum" anlamına gelir ve fatura
 * imzalarında kullanılan taahhüt budur.
 */
export type CommitmentType =
  | 'proof-of-origin'
  | 'proof-of-receipt'
  | 'proof-of-delivery'
  | 'proof-of-sender'
  | 'proof-of-approval'
  | 'proof-of-creation'

/** Taahhüt türü → OID. */
export const COMMITMENT_OID: Readonly<Record<CommitmentType, string>> = {
  'proof-of-origin': '1.2.840.113549.1.9.16.6.1',
  'proof-of-receipt': '1.2.840.113549.1.9.16.6.2',
  'proof-of-delivery': '1.2.840.113549.1.9.16.6.3',
  'proof-of-sender': '1.2.840.113549.1.9.16.6.4',
  'proof-of-approval': '1.2.840.113549.1.9.16.6.5',
  'proof-of-creation': '1.2.840.113549.1.9.16.6.6',
}

/**
 * UBL ad alanları — imzanın `ext:UBLExtensions` içine yerleştirilebilmesi
 * için gerekli.
 */
export const Ubl = {
  EXTENSION: 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
} as const

/**
 * Türkiye elektronik imza kullanım profillerinin nesne tanımlayıcıları.
 *
 * **Köken uyarısı.** Bu değerler kamuya açık TR belgelerinden derlendi ve
 * bu kütüphane tarafından bağımsız olarak doğrulanamadı. Kullanmadan önce
 * kendi yükümlülüğünüz açısından teyit edin — yanlış bir politika OID'i
 * imzayı yapısal olarak geçerli ama hukuken beklediğinizden farklı kılar.
 *
 * Zorunlu değildirler: {@link SignaturePolicy} açık bir OID ve özet
 * kabul eder, dolayısıyla bu tabloya bağlı kalmak gerekmez.
 */
export const TR_POLICY_OID = {
  /** Resmî yazışma profili. */
  P2: '2.16.792.1.61.0.1.5070.3.1.1',
  /** Yapılandırılmış veri (e-Fatura) profili. */
  P3: '2.16.792.1.61.0.1.5070.3.2.1',
  /** Yapılandırılmamış veri (PDF) profili. */
  P4: '2.16.792.1.61.0.1.5070.3.3.1',
} as const
