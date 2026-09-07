import {
  asInteger,
  asOid,
  asSequence,
  asSet,
  asString,
  asTime,
  decodeDer,
  type DerNode,
} from '../asn1/der.js'
import { toHex } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

/**
 * X.509 sertifikasının imza için gereken alanlarını okur.
 *
 * Node'un kendi `X509Certificate` sınıfı bu bilgilerin çoğunu verir, ama iki
 * alanı XAdES'in istediği biçimde vermez ve ikisi de doğrudan uyumluluk
 * sorunudur:
 *
 * - **Seri numarası.** Node onu onaltılık dize olarak sunar; `ds:X509Serial
 *   Number` ise ONDALIK bir tam sayı ister. `xadesjs#52` tam olarak bu
 *   yüzden açıldı: onaltılık yazılan imzaları dışarıdaki doğrulayıcılar
 *   reddediyordu.
 * - **Düzenleyen adı.** Node çok satırlı OpenSSL biçimi üretir
 *   (`C=TR\nO=…`); `ds:X509IssuerName` ise RFC 4514 dizesi ister — ters
 *   sırada, virgülle ayrılmış ve kaçırılmış.
 *
 * Bu yüzden sertifika kendi DER okuyucumuzla ayrıştırılıyor.
 */

/** Ayrıştırılmış sertifika bilgisi. */
export interface CertificateInfo {
  /** Sertifikanın DER kodlaması — özet bunun üzerinden alınır. */
  readonly der: Uint8Array
  /** Düzenleyen ayırt edici adı, RFC 4514 biçiminde. */
  readonly issuerName: string
  /** Konu ayırt edici adı, RFC 4514 biçiminde. */
  readonly subjectName: string
  /** Seri numarası — 20 bayta kadar çıkabildiği için `bigint`. */
  readonly serialNumber: bigint
  /** Geçerlilik başlangıcı. */
  readonly notBefore: Date
  /** Geçerlilik bitişi. */
  readonly notAfter: Date
  /** Açık anahtar algoritması. */
  readonly keyAlgorithm: 'rsa' | 'ec' | 'other'
  /**
   * Konu içindeki `serialNumber` özniteliği (OID 2.5.4.5).
   *
   * Türkiye'de mali mühür ve NES sertifikalarında VKN ya da TCKN bu alanda
   * taşınır. Sertifikanın SERİ NUMARASI ile karıştırılmamalı; ikisi ayrı
   * alanlardır ve aynı adı taşımaları talihsizliktir.
   */
  readonly subjectSerialNumber?: string
}

/**
 * RFC 4514 §3'ün kısa adlarına, sahada yaygın olarak yazılan birkaç ek.
 *
 * Listede olmayan öznitelikler noktalı OID ve `#onaltılık` değerle yazılır —
 * RFC 4514'ün kendi kuralı budur ve tahmin etmekten iyidir.
 */
const ATTRIBUTE_NAMES: Readonly<Record<string, string>> = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'T',
  '2.5.4.42': 'G',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'E',
}

const OID_SUBJECT_SERIAL = '2.5.4.5'
const OID_RSA = '1.2.840.113549.1.1.1'
const OID_EC = '1.2.840.10045.2.1'

/**
 * RFC 4514 §2.4 uyarınca bir öznitelik değerini kaçırır.
 *
 * @param value - Ham değer
 * @returns Kaçırılmış değer
 */
const escapeAttributeValue = (value: string): string => {
  let out = value.replace(/([",+;<>\\])/g, '\\$1')
  // Baştaki `#` ve boşluk, sondaki boşluk kaçırılır; aksi hâlde dize
  // yeniden okunduğunda farklı ayrıştırılır.
  if (out.startsWith('#') || out.startsWith(' ')) out = `\\${out}`
  if (out.endsWith(' ') && !out.endsWith('\\ ')) out = `${out.slice(0, -1)}\\ `
  // Null karakteri kaçırmanın tek yolu onaltılık gösterim.
  return out.replace(/\0/g, '\\00')
}

/**
 * `Name` yapısını RFC 4514 dizesine çevirir.
 *
 * Sıra TERSTİR: DER'de en genelden en özele yazılan bileşenler, dizede en
 * özelden en genele okunur (`CN=…,O=…,C=TR`). Bu ters çevirmeyi atlamak,
 * dizeyi karşılaştırma yoluyla eşleştiren doğrulayıcılarda sessiz bir
 * uyumsuzluk üretir.
 */
const formatName = (name: DerNode): string => {
  const parts: string[] = []
  for (const rdn of asSequence(name)) {
    const pieces: string[] = []
    for (const attribute of asSet(rdn)) {
      const fields = asSequence(attribute)
      const typeNode = fields[0]
      const valueNode = fields[1]
      if (typeNode === undefined || valueNode === undefined) continue
      const oid = asOid(typeNode)
      const label = ATTRIBUTE_NAMES[oid]
      if (label === undefined) {
        // Tanınmayan öznitelik: OID ve ham DER değeri (RFC 4514 §2.4).
        pieces.push(`${oid}=#${toHex(valueNode.raw)}`)
      } else {
        pieces.push(`${label}=${escapeAttributeValue(asString(valueNode))}`)
      }
    }
    // Çok değerli RDN bileşenleri `+` ile birleşir.
    if (pieces.length > 0) parts.push(pieces.join('+'))
  }
  return parts.reverse().join(',')
}

/**
 * DER kodlu bir X.509 sertifikasını okur.
 *
 * @param der - Sertifikanın DER kodlaması
 * @returns İmza için gereken alanlar
 * @throws {DerParseError} Yapı X.509 değilse
 *
 * @example
 * ```ts
 * const info = readCertificate(bundle.certificate)
 * info.issuerName    // 'CN=Ornek Kok CA,O=Ornek,C=TR'
 * info.serialNumber  // 1234567890123456789n — ondalık yazılmaya hazır
 * ```
 */
export const readCertificate = (der: Uint8Array): CertificateInfo => {
  const certificate = asSequence(decodeDer(der))
  const tbs = certificate[0]
  if (tbs === undefined) throw new DerParseError(0, 'tbsCertificate yok.')
  const fields = asSequence(tbs)

  // `version [0] EXPLICIT` isteğe bağlıdır; varsa diğer alanlar bir kayar.
  const versioned = fields[0]?.tagClass === 'context' && fields[0].tagNumber === 0
  const at = (index: number): DerNode => {
    const node = fields[versioned ? index + 1 : index]
    if (node === undefined)
      throw new DerParseError(0, `tbsCertificate alanı eksik: ${String(index)}`)
    return node
  }

  const serialNumber = asInteger(at(0))
  const issuer = at(2)
  const validity = asSequence(at(3))
  const subject = at(4)
  const subjectPublicKeyInfo = asSequence(at(5))

  const notBeforeNode = validity[0]
  const notAfterNode = validity[1]
  if (notBeforeNode === undefined || notAfterNode === undefined) {
    throw new DerParseError(0, 'Geçerlilik aralığı eksik.')
  }

  const algorithmOid = asOid(asSequence(subjectPublicKeyInfo[0] ?? tbs)[0] ?? tbs)
  const keyAlgorithm = algorithmOid === OID_RSA ? 'rsa' : algorithmOid === OID_EC ? 'ec' : 'other'

  // Konudaki `serialNumber` özniteliği — TR'de VKN/TCKN taşır.
  let subjectSerialNumber: string | undefined
  for (const rdn of asSequence(subject)) {
    for (const attribute of asSet(rdn)) {
      const attributeFields = asSequence(attribute)
      const typeNode = attributeFields[0]
      const valueNode = attributeFields[1]
      if (typeNode === undefined || valueNode === undefined) continue
      if (asOid(typeNode) === OID_SUBJECT_SERIAL) subjectSerialNumber = asString(valueNode)
    }
  }

  return {
    der,
    issuerName: formatName(issuer),
    subjectName: formatName(subject),
    serialNumber,
    notBefore: asTime(notBeforeNode),
    notAfter: asTime(notAfterNode),
    keyAlgorithm,
    ...(subjectSerialNumber === undefined ? {} : { subjectSerialNumber }),
  }
}
