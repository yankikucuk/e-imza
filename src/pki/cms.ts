import { createHash, createVerify, X509Certificate } from 'node:crypto'

import {
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asSet,
  decodeDer,
  DerTag,
  findContext,
  type DerNode,
} from '../asn1/der.js'
import { timingSafeEqual } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

/**
 * CMS `SignedData` okuma ve doğrulama — RFC 5652.
 *
 * Bu modül XAdES-T için yazıldı: RFC 3161 zaman damgası jetonu bir CMS
 * `SignedData`'dır. Aynı çekirdek CAdES'in de temeli olacak; o yüzden
 * kapsam "zaman damgası kadarı" değil, "imzalı CMS kadarı".
 *
 * Yalnızca **okuma ve doğrulama** var. CMS üretimi CAdES'in işi ve o
 * geldiğinde buraya eklenecek.
 */

/** CMS ve PKCS#9 nesne tanımlayıcıları. */
export const CmsOid = {
  DATA: '1.2.840.113549.1.7.1',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  /** `id-ct-TSTInfo` — zaman damgası jetonunun sarmaladığı içerik. */
  TST_INFO: '1.2.840.113549.1.9.16.1.4',
  CONTENT_TYPE: '1.2.840.113549.1.9.3',
  MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
  SIGNING_TIME: '1.2.840.113549.1.9.5',
} as const

/** Özet algoritması OID'leri → `node:crypto` adları. */
const DIGEST_BY_OID: Readonly<Record<string, string>> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '2.16.840.1.101.3.4.2.4': 'sha224',
}

/**
 * İmza algoritması OID'leri → özet adı.
 *
 * `rsaEncryption` burada kasten var: pek çok üretici `SignerInfo.signature
 * Algorithm` alanına imza algoritmasını değil ham `rsaEncryption`'ı yazar ve
 * özeti ayrı `digestAlgorithm` alanında bildirir. İkisini de karşılamak
 * gerekiyor.
 */
const SIGNATURE_BY_OID: Readonly<Record<string, { hash?: string; kind: 'rsa' | 'ec' }>> = {
  '1.2.840.113549.1.1.1': { kind: 'rsa' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', kind: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', kind: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', kind: 'rsa' },
  '1.2.840.10045.2.1': { kind: 'ec' },
  '1.2.840.10045.4.3.2': { hash: 'sha256', kind: 'ec' },
  '1.2.840.10045.4.3.3': { hash: 'sha384', kind: 'ec' },
  '1.2.840.10045.4.3.4': { hash: 'sha512', kind: 'ec' },
}

/** Çözümlenmiş `SignerInfo`. */
export interface CmsSignerInfo {
  /** İmzalayanı gösteren `issuerAndSerialNumber` — düzenleyen adı DER'i. */
  readonly issuerDer?: Uint8Array
  /** İmzalayanın sertifika seri numarası. */
  readonly serialNumber?: bigint
  /** `subjectKeyIdentifier` ile gösterilmişse. */
  readonly subjectKeyIdentifier?: Uint8Array
  /** Özet algoritması (`node:crypto` adı). */
  readonly digestAlgorithm: string
  /** İmzalanmış öznitelikler; yoksa `undefined`. */
  readonly signedAttributes?: readonly DerNode[]
  /**
   * İmzalanmış özniteliklerin **DER olarak yeniden kodlanmış** hâli.
   *
   * RFC 5652 §5.4: imza, `signedAttrs`ın TAM DER kodlaması üzerinde
   * hesaplanır ve o kodlamada dış etiket `[0] IMPLICIT` değil `SET`tir.
   * Kaynaktaki baytların yalnızca ilk baytı değiştirilerek elde edilir;
   * yeniden serileştirmek, kaynak tam DER değilse farklı bayt üretir ve
   * imza tutmaz. `PKI.js#402` bu ailedeki bir hata.
   */
  readonly signedAttributesDer?: Uint8Array
  readonly signatureAlgorithmOid: string
  readonly signature: Uint8Array
  /**
   * İmzalanmamış öznitelikler; yoksa `undefined`.
   *
   * İmzaya dâhil DEĞİLLERDİR — zaman damgası ve iptal verisi bu yüzden
   * imza atıldıktan sonra eklenebiliyor.
   */
  readonly unsignedAttributes?: readonly DerNode[]
}

/** Çözümlenmiş `SignedData`. */
export interface CmsSignedData {
  /** Sarmalanan içeriğin türü (ör. {@link CmsOid.TST_INFO}). */
  readonly contentType: string
  /** Sarmalanan içerik; ayrık (detached) imzada `undefined`. */
  readonly content?: Uint8Array
  /** Gömülü sertifikalar (DER). */
  readonly certificates: readonly Uint8Array[]
  readonly signerInfos: readonly CmsSignerInfo[]
}

/**
 * CMS `ContentInfo` sarmalayıcısından `SignedData` çözümler.
 *
 * @param bytes - `ContentInfo` DER kodlaması
 * @returns Çözümlenmiş yapı
 * @throws {DerParseError} Yapı CMS `SignedData` değilse
 */
export const parseCmsSignedData = (bytes: Uint8Array): CmsSignedData => {
  const contentInfo = asSequence(decodeDer(bytes))
  const typeNode = contentInfo[0]
  const contentNode = contentInfo[1]
  if (typeNode === undefined || contentNode === undefined) {
    throw new DerParseError(0, 'ContentInfo yapısı eksik.')
  }
  if (asOid(typeNode) !== CmsOid.SIGNED_DATA) {
    throw new DerParseError(0, `Beklenen id-signedData; bulunan ${asOid(typeNode)}`)
  }
  const signedDataNode = contentNode.children[0]
  if (signedDataNode === undefined) throw new DerParseError(0, 'SignedData içeriği boş.')

  const fields = asSequence(signedDataNode)
  // SEQUENCE { version, digestAlgorithms, encapContentInfo, [0] certs?,
  //            [1] crls?, signerInfos }
  const encapNode = fields[2]
  if (encapNode === undefined) throw new DerParseError(0, 'encapContentInfo yok.')
  const encap = asSequence(encapNode)
  const contentTypeNode = encap[0]
  if (contentTypeNode === undefined) throw new DerParseError(0, 'eContentType yok.')
  const eContent = encap[1]?.children[0]

  const certificatesNode = findContext(fields, 0)
  const certificates =
    certificatesNode === undefined
      ? []
      : certificatesNode.children
          // CertificateChoices bir CHOICE; yalnızca düz X.509 alınır.
          .filter((node) => node.tagClass === 'universal' && node.tagNumber === DerTag.SEQUENCE)
          .map((node) => node.raw)

  // signerInfos, yapının SON alanıdır ve bir SET'tir.
  const signerInfosNode = [...fields]
    .reverse()
    .find((node) => node.tagClass === 'universal' && node.tagNumber === DerTag.SET)
  if (signerInfosNode === undefined) throw new DerParseError(0, 'signerInfos yok.')

  return {
    contentType: asOid(contentTypeNode),
    ...(eContent === undefined ? {} : { content: asOctetString(eContent) }),
    certificates,
    signerInfos: asSet(signerInfosNode).map(parseSignerInfo),
  }
}

/** Tek bir `SignerInfo` çözümler. */
const parseSignerInfo = (node: DerNode): CmsSignerInfo => {
  const fields = asSequence(node)
  const sid = fields[1]
  const digestAlgorithmNode = fields[2]
  if (sid === undefined || digestAlgorithmNode === undefined) {
    throw new DerParseError(0, 'SignerInfo yapısı eksik.')
  }

  const digestOid = asOid(asSequence(digestAlgorithmNode)[0] ?? digestAlgorithmNode)
  const digestAlgorithm = DIGEST_BY_OID[digestOid]
  if (digestAlgorithm === undefined) {
    throw new DerParseError(0, `Desteklenmeyen özet algoritması: ${digestOid}`)
  }

  // sid CHOICE: issuerAndSerialNumber (SEQUENCE) ya da [0] subjectKeyIdentifier.
  let issuerDer: Uint8Array | undefined
  let serialNumber: bigint | undefined
  let subjectKeyIdentifier: Uint8Array | undefined
  if (sid.tagClass === 'context' && sid.tagNumber === 0) {
    subjectKeyIdentifier = sid.content
  } else {
    const parts = asSequence(sid)
    const issuerNode = parts[0]
    const serialNode = parts[1]
    if (issuerNode === undefined || serialNode === undefined) {
      throw new DerParseError(0, 'issuerAndSerialNumber eksik.')
    }
    issuerDer = issuerNode.raw
    serialNumber = asInteger(serialNode)
  }

  // [0] IMPLICIT signedAttrs — varsa üçüncü alandan sonra gelir.
  const signedAttrsNode = fields.find((f) => f.tagClass === 'context' && f.tagNumber === 0)
  let signedAttributesDer: Uint8Array | undefined
  if (signedAttrsNode !== undefined) {
    // Dış etiketi `[0] IMPLICIT`ten `SET`e çevir: RFC 5652 §5.4 imzanın
    // bu kodlama üzerinde hesaplandığını söyler. Yeniden serileştirmek
    // yerine ilk BAYTI değiştiriyoruz — kaynağın geri kalanı aynen kalsın.
    signedAttributesDer = new Uint8Array(signedAttrsNode.raw)
    signedAttributesDer[0] = 0x31
  }

  const unsignedIndex = fields.findIndex((f) => f.tagClass === 'context' && f.tagNumber === 1)
  const unsignedNode = unsignedIndex === -1 ? undefined : fields[unsignedIndex]
  const tail = unsignedIndex === -1 ? fields : fields.slice(0, unsignedIndex)
  const signature = tail[tail.length - 1]
  const signatureAlgorithmNode = tail[tail.length - 2]
  if (signature === undefined || signatureAlgorithmNode === undefined) {
    throw new DerParseError(0, 'SignerInfo imza alanları eksik.')
  }

  return {
    ...(issuerDer === undefined ? {} : { issuerDer }),
    ...(serialNumber === undefined ? {} : { serialNumber }),
    ...(subjectKeyIdentifier === undefined ? {} : { subjectKeyIdentifier }),
    digestAlgorithm,
    ...(signedAttrsNode === undefined ? {} : { signedAttributes: signedAttrsNode.children }),
    ...(signedAttributesDer === undefined ? {} : { signedAttributesDer }),
    signatureAlgorithmOid: asOid(asSequence(signatureAlgorithmNode)[0] ?? signatureAlgorithmNode),
    signature: asOctetString(signature),
    ...(unsignedNode === undefined ? {} : { unsignedAttributes: unsignedNode.children }),
  }
}

/**
 * Bir öznitelik listesinde belirli OID'in TÜM değerlerini verir.
 *
 * @param attributes - Öznitelik düğümleri
 * @param oid - Aranan öznitelik OID'i
 * @returns Bulunan değerler; yoksa boş
 */
export const attributeValues = (
  attributes: readonly DerNode[] | undefined,
  oid: string,
): readonly DerNode[] => {
  const out: DerNode[] = []
  for (const attribute of attributes ?? []) {
    const fields = asSequence(attribute)
    const typeNode = fields[0]
    const valuesNode = fields[1]
    if (typeNode === undefined || valuesNode === undefined) continue
    if (asOid(typeNode) === oid) out.push(...asSet(valuesNode))
  }
  return out
}

/**
 * `SignerInfo` içindeki bir imzalanmış özniteliğin ilk değerini verir.
 *
 * @param signer - Çözümlenmiş imzacı
 * @param oid - Aranan öznitelik OID'i
 * @returns Öznitelik değeri ya da `undefined`
 */
export const signedAttribute = (signer: CmsSignerInfo, oid: string): DerNode | undefined => {
  for (const attribute of signer.signedAttributes ?? []) {
    const fields = asSequence(attribute)
    const typeNode = fields[0]
    const valuesNode = fields[1]
    if (typeNode === undefined || valuesNode === undefined) continue
    if (asOid(typeNode) === oid) return asSet(valuesNode)[0]
  }
  return undefined
}

/** {@link verifyCmsSigner} sonucu. */
export type CmsVerification =
  | { readonly valid: true; readonly certificate: Uint8Array }
  | { readonly valid: false; readonly reason: string }

/**
 * Bir `SignerInfo`yu doğrular.
 *
 * İki bağ birlikte kontrol edilir ve ikisi de gereklidir:
 * 1. `messageDigest` imzalanmış özniteliği, sarmalanan içeriğin özetine eşit,
 * 2. `signature`, `signedAttrs`ın DER kodlaması üzerinde sertifikanın açık
 *    anahtarıyla doğrulanıyor.
 *
 * Yalnızca ikincisini kontrol etmek, imzacının BAŞKA bir içeriğe attığı
 * imzanın bu içeriğe iliştirilmesine izin verirdi.
 *
 * @param signed - Çözümlenmiş `SignedData`
 * @param signer - Doğrulanacak imzacı
 * @param content - Sarmalanan içerik; ayrık imzada dışarıdan verilir
 * @returns Doğrulama sonucu; geçersizlik hata değil, sonuçtur
 */
export const verifyCmsSigner = (
  signed: CmsSignedData,
  signer: CmsSignerInfo,
  content?: Uint8Array,
): CmsVerification => {
  const payload = content ?? signed.content
  if (payload === undefined) {
    return { valid: false, reason: 'İmzalanan içerik ne gömülü ne de dışarıdan verildi.' }
  }

  const certificateDer = findSignerCertificate(signed, signer)
  if (certificateDer === undefined) {
    return { valid: false, reason: 'İmzacının sertifikası CMS içinde bulunamadı.' }
  }

  let signedBytes: Uint8Array
  if (signer.signedAttributesDer === undefined) {
    // İmzalanmış öznitelik yoksa imza doğrudan içeriğin üzerindedir.
    signedBytes = payload
  } else {
    const declared = signedAttribute(signer, CmsOid.MESSAGE_DIGEST)
    if (declared === undefined) {
      return { valid: false, reason: 'messageDigest imzalanmış özniteliği yok.' }
    }
    const actual = new Uint8Array(
      createHash(signer.digestAlgorithm).update(Buffer.from(payload)).digest(),
    )
    if (!timingSafeEqual(actual, asOctetString(declared))) {
      return { valid: false, reason: 'messageDigest içerikle eşleşmiyor.' }
    }
    signedBytes = signer.signedAttributesDer
  }

  const algorithm = SIGNATURE_BY_OID[signer.signatureAlgorithmOid]
  if (algorithm === undefined) {
    return {
      valid: false,
      reason: `Desteklenmeyen imza algoritması: ${signer.signatureAlgorithmOid}`,
    }
  }
  // `rsaEncryption` gibi özet taşımayan tanımlayıcılarda özet ayrı alandan.
  const hash = algorithm.hash ?? signer.digestAlgorithm

  try {
    const certificate = new X509Certificate(Buffer.from(certificateDer))
    const verifier = createVerify(hash)
    verifier.update(Buffer.from(signedBytes))
    const ok = verifier.verify(certificate.publicKey, Buffer.from(signer.signature))
    return ok
      ? { valid: true, certificate: certificateDer }
      : { valid: false, reason: 'CMS imza değeri doğrulanmadı.' }
  } catch (error) {
    return {
      valid: false,
      reason: `CMS imzası değerlendirilemedi: ${error instanceof Error ? error.message : String(error)}`,
    }
  }
}

/** İmzacıyı gösteren sertifikayı CMS içinden bulur. */
const findSignerCertificate = (
  signed: CmsSignedData,
  signer: CmsSignerInfo,
): Uint8Array | undefined => {
  for (const der of signed.certificates) {
    const fields = asSequence(asSequence(decodeDer(der))[0] ?? decodeDer(der))
    const versioned = fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0
    const serialNode = fields[versioned ? 1 : 0]
    const issuerNode = fields[versioned ? 3 : 2]
    if (serialNode === undefined || issuerNode === undefined) continue

    if (signer.serialNumber !== undefined && signer.issuerDer !== undefined) {
      if (asInteger(serialNode) !== signer.serialNumber) continue
      if (!timingSafeEqual(issuerNode.raw, signer.issuerDer)) continue
      return der
    }
  }
  // `subjectKeyIdentifier` ile gösterilen imzacılar için tek sertifika varsa
  // o kullanılır; birden çoksa belirsizlik var demektir ve seçilmez.
  if (signer.subjectKeyIdentifier !== undefined && signed.certificates.length === 1) {
    return signed.certificates[0]
  }
  return undefined
}
