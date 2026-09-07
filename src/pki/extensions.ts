import { asOid, asSequence, decodeDer, DerTag, findContext, type DerNode } from '../asn1/der.js'
import { DerParseError } from '../core/errors.js'

/**
 * X.509 uzantılarından iptal denetimi için gereken adresleri çıkarır.
 *
 * LT seviyesine yükseltmek, sertifikanın iptal durumunu kanıtlayan veriyi
 * imzaya gömmek demek. O veriyi nereden alacağınız sertifikanın kendi
 * içinde yazılıdır: OCSP yanıtlayıcısının adresi `AuthorityInfoAccess`
 * uzantısında, CRL adresi `CRLDistributionPoints` uzantısında.
 *
 * Bu modül yalnızca adresi **okur**; almak çağıranın işi.
 */

const OID = {
  AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1',
  CRL_DISTRIBUTION_POINTS: '2.5.29.31',
  OCSP: '1.3.6.1.5.5.7.48.1',
  CA_ISSUERS: '1.3.6.1.5.5.7.48.2',
} as const

/** `GeneralName` içindeki `uniformResourceIdentifier` seçeneği — `[6] IMPLICIT`. */
const GENERAL_NAME_URI = 6

/** Sertifikanın `tbsCertificate` alanlarını verir. */
const tbsFields = (der: Uint8Array): readonly DerNode[] => {
  const certificate = asSequence(decodeDer(der))
  const tbs = certificate[0]
  if (tbs === undefined) throw new DerParseError(0, 'tbsCertificate yok.')
  return asSequence(tbs)
}

/**
 * Sertifikanın uzantılarını verir.
 *
 * `extensions [3] EXPLICIT` alanı isteğe bağlıdır ve yalnızca v3
 * sertifikalarda bulunur.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns `Extension` düğümleri; uzantı yoksa boş
 */
export const certificateExtensions = (der: Uint8Array): readonly DerNode[] => {
  const extensionsNode = findContext(tbsFields(der), 3)
  if (extensionsNode === undefined) return []
  const inner = extensionsNode.children[0]
  return inner === undefined ? [] : asSequence(inner)
}

/**
 * Belirli bir uzantının değerini verir.
 *
 * @param der - Sertifikanın DER kodlaması
 * @param oid - Uzantı OID'i
 * @returns Uzantının `extnValue` içeriği çözümlenmiş hâlde, ya da `undefined`
 */
export const certificateExtension = (der: Uint8Array, oid: string): DerNode | undefined => {
  for (const extension of certificateExtensions(der)) {
    const fields = asSequence(extension)
    const oidNode = fields[0]
    if (oidNode === undefined || asOid(oidNode) !== oid) continue
    // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue OCTET STRING }
    // `critical` isteğe bağlı olduğu için değer son alandır.
    const valueNode = fields[fields.length - 1]
    if (valueNode === undefined) return undefined
    return decodeDer(valueNode.content)
  }
  return undefined
}

/** `GeneralName` listesinden URI seçeneklerini toplar. */
const uriNames = (nodes: readonly DerNode[]): readonly string[] => {
  const out: string[] = []
  for (const node of nodes) {
    if (node.tagClass !== 'context' || node.tagNumber !== GENERAL_NAME_URI) continue
    // `[6] IMPLICIT IA5String` — içerik ham ASCII.
    out.push(new TextDecoder('latin1').decode(node.content))
  }
  return out
}

/**
 * Sertifikanın OCSP yanıtlayıcı adreslerini verir.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns Bulunan adresler; yoksa boş
 *
 * @example
 * ```ts
 * const [adres] = ocspResponderUrls(sertifika)
 * if (adres === undefined) throw new Error('Sertifikada OCSP adresi yok')
 * ```
 */
export const ocspResponderUrls = (der: Uint8Array): readonly string[] =>
  accessLocations(der, OID.OCSP)

/**
 * Sertifikayı düzenleyen sertifikanın indirilebileceği adresleri verir.
 *
 * Zincir eksikse (`caIssuers`) buradan tamamlanabilir.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns Bulunan adresler; yoksa boş
 */
export const caIssuerUrls = (der: Uint8Array): readonly string[] =>
  accessLocations(der, OID.CA_ISSUERS)

/** `AuthorityInfoAccess` içinde belirli bir erişim yöntemine ait adresler. */
const accessLocations = (der: Uint8Array, method: string): readonly string[] => {
  const aia = certificateExtension(der, OID.AUTHORITY_INFO_ACCESS)
  if (aia === undefined) return []
  const out: string[] = []
  for (const description of asSequence(aia)) {
    const fields = asSequence(description)
    const methodNode = fields[0]
    const locationNode = fields[1]
    if (methodNode === undefined || locationNode === undefined) continue
    if (asOid(methodNode) !== method) continue
    out.push(...uriNames([locationNode]))
  }
  return out
}

/**
 * Sertifikanın CRL dağıtım noktası adreslerini verir.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns Bulunan adresler; yoksa boş
 */
export const crlDistributionUrls = (der: Uint8Array): readonly string[] => {
  const cdp = certificateExtension(der, OID.CRL_DISTRIBUTION_POINTS)
  if (cdp === undefined) return []
  const out: string[] = []
  for (const point of asSequence(cdp)) {
    // DistributionPoint ::= SEQUENCE { distributionPoint [0] OPTIONAL, … }
    const name = findContext(asSequence(point), 0)
    if (name === undefined) continue
    // DistributionPointName ::= CHOICE { fullName [0] GeneralNames, … }
    const fullName = findContext(name.children, 0)
    if (fullName === undefined) continue
    out.push(...uriNames(fullName.children))
  }
  return out
}

/**
 * Sertifikanın konu ve düzenleyen adlarının DER kodlamalarını verir.
 *
 * OCSP'nin `CertID` yapısı düzenleyen adının özetini istiyor ve o özet
 * **DER kodlaması üzerinden** alınmalı; ayrıştırılıp yeniden kodlanmış
 * hâli üzerinden değil.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns Ham `Name` baytları
 */
export const certificateNames = (
  der: Uint8Array,
): { readonly issuer: Uint8Array; readonly subject: Uint8Array } => {
  const fields = tbsFields(der)
  const versioned = fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0
  const issuer = fields[versioned ? 3 : 2]
  const subject = fields[versioned ? 5 : 4]
  if (issuer === undefined || subject === undefined) {
    throw new DerParseError(0, 'Sertifikada ad alanları eksik.')
  }
  return { issuer: issuer.raw, subject: subject.raw }
}

/**
 * Sertifikanın açık anahtar bitlerini verir (dolgu baytı olmadan).
 *
 * OCSP `CertID.issuerKeyHash` alanı, düzenleyenin açık anahtarının BIT
 * STRING **içeriğinin** özetidir — `SubjectPublicKeyInfo`nun tamamının
 * değil. Bu ayrım sıkça karıştırılır ve karıştırıldığında yanıtlayıcı
 * "unknown" döner.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns Açık anahtar bitleri
 */
export const publicKeyBits = (der: Uint8Array): Uint8Array => {
  const fields = tbsFields(der)
  const versioned = fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0
  const spki = fields[versioned ? 6 : 5]
  if (spki === undefined) throw new DerParseError(0, 'SubjectPublicKeyInfo yok.')
  const bits = asSequence(spki)[1]
  if (bits?.tagNumber !== DerTag.BIT_STRING) {
    throw new DerParseError(0, 'Açık anahtar biti yok.')
  }
  // İlk bayt kullanılmayan bit sayısı; anahtar bitlerinin parçası değil.
  return bits.content.subarray(1)
}

/**
 * Sertifikanın seri numarasını ham DER düğümü olarak verir.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns `INTEGER` düğümü
 */
export const serialNumberNode = (der: Uint8Array): DerNode => {
  const fields = tbsFields(der)
  const versioned = fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0
  const node = fields[versioned ? 1 : 0]
  if (node === undefined) throw new DerParseError(0, 'Seri numarası yok.')
  return node
}
