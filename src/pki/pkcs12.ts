import { createHmac, createPrivateKey, X509Certificate, type KeyObject } from 'node:crypto'

import {
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asSet,
  asString,
  decodeDer,
  findContext,
  type DerNode,
} from '../asn1/der.js'
import { timingSafeEqual, toBase64 } from '../core/bytes.js'
import { Pkcs12Error } from '../core/errors.js'

import { decryptPbe, passwordEncodings, pkcs12Kdf, Pkcs12KeyType, type Pkcs12Hash } from './pbe.js'

/**
 * PKCS#12 (`.p12` / `.pfx`) kap okuyucusu — RFC 7292.
 *
 * Türkiye'de mali mühür ve NES sertifikaları bu biçimde dağıtılır. Kabın
 * içindeki iki bölüm (sertifikalar ve özel anahtar) ayrı ayrı şifrelenir ve
 * eski araçlar sertifika bölümü için `pbeWithSHAAnd40BitRC2-CBC` seçer —
 * Node'un kriptografisinde artık bulunmayan bir algoritma. Bu yüzden RC2 ve
 * RC4 paketin içinde saf JavaScript olarak var; onlarsız bu dosyaların
 * önemli bir kısmı Node'da hiç açılamaz.
 */

const OID = {
  DATA: '1.2.840.113549.1.7.1',
  ENCRYPTED_DATA: '1.2.840.113549.1.7.6',
  KEY_BAG: '1.2.840.113549.1.12.10.1.1',
  SHROUDED_KEY_BAG: '1.2.840.113549.1.12.10.1.2',
  CERT_BAG: '1.2.840.113549.1.12.10.1.3',
  X509_CERTIFICATE: '1.2.840.113549.1.9.22.1',
  FRIENDLY_NAME: '1.2.840.113549.1.9.20',
  LOCAL_KEY_ID: '1.2.840.113549.1.9.21',
} as const

/** MAC doğrulamasında geçen özet OID'leri. */
const MAC_HASH: Readonly<Record<string, Pkcs12Hash>> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
}

/** {@link loadPkcs12} sonucu. */
export interface Pkcs12Bundle {
  /** Kaptan çıkan özel anahtar, imzalamaya hazır. */
  readonly privateKey: KeyObject
  /** Özel anahtara ait uç sertifika (DER). */
  readonly certificate: Uint8Array
  /**
   * Kaptaki diğer sertifikalar — uçtan köke doğru sıralanmış.
   *
   * Sıralama "her sertifikanın bir öncekini imzalamış olması" kuralına göre
   * kurulur; zincire bağlanamayan sertifikalar sona eklenir. Kaplar zaman
   * zaman ilgisiz sertifika da taşır ve onları atmak, kullanıcıya ait bir
   * veriyi sessizce kaybetmek olurdu.
   */
  readonly chain: readonly Uint8Array[]
  /** Kapta yazılıysa dostane ad (`friendlyName`). */
  readonly friendlyName?: string
}

/** {@link loadPkcs12} seçenekleri. */
export interface LoadPkcs12Options {
  /**
   * Bütünlük (MAC) doğrulaması yapılsın mı. Varsayılan `true`.
   *
   * Kapatmak yalnızca MAC'i bozuk ama içeriği okunabilir bir dosyayı
   * kurtarmak için anlamlıdır; normal akışta açık kalmalıdır çünkü MAC,
   * parolanın doğruluğunu içerik çözülmeden önce söyleyen tek işarettir.
   */
  readonly verifyMac?: boolean
}

/** Kaptan çıkarılan ham torba. */
interface SafeBag {
  readonly bagId: string
  readonly value: DerNode
  readonly friendlyName?: string
  readonly localKeyId?: string
}

/**
 * PKCS#12 kabını açar.
 *
 * @param bytes - `.p12` / `.pfx` dosyasının içeriği
 * @param password - Kap parolası
 * @param options - {@link LoadPkcs12Options}
 * @returns Özel anahtar, uç sertifika ve zincir
 * @throws {Pkcs12Error} Parola yanlış, bütünlük bozuk ya da biçim desteklenmiyorsa
 *
 * @example
 * ```ts
 * const { privateKey, certificate } = loadPkcs12(
 *   new Uint8Array(readFileSync('mali-muhur.p12')),
 *   process.env.MUHUR_SIFRESI ?? '',
 * )
 * ```
 */
export const loadPkcs12 = (
  bytes: Uint8Array,
  password: string,
  options: LoadPkcs12Options = {},
): Pkcs12Bundle => {
  const pfx = asSequence(decodeDer(bytes))
  const authSafeNode = pfx[1]
  if (authSafeNode === undefined) throw new Pkcs12Error('malformed', 'authSafe alanı yok.')

  const authSafeContent = contentInfoData(authSafeNode)
  if (authSafeContent === undefined) {
    throw new Pkcs12Error('unsupported', 'İmzalı (signedData) PKCS#12 kapları desteklenmiyor.')
  }

  if (options.verifyMac ?? true) {
    const macData = pfx[2]
    if (macData !== undefined) verifyMac(macData, authSafeContent, password)
  }

  const bags: SafeBag[] = []
  for (const contentInfo of asSequence(decodeDer(authSafeContent))) {
    bags.push(...readSafeContents(contentInfo, password))
  }

  const certificates: { readonly der: Uint8Array; readonly localKeyId?: string }[] = []
  let privateKeyDer: Uint8Array | undefined
  let keyLocalId: string | undefined
  let friendlyName: string | undefined

  for (const bag of bags) {
    if (bag.bagId === OID.CERT_BAG) {
      const [certIdNode, certValueNode] = asSequence(bag.value)
      if (certIdNode === undefined || certValueNode === undefined) continue
      if (asOid(certIdNode) !== OID.X509_CERTIFICATE) continue
      const inner = certValueNode.children[0]
      if (inner === undefined) continue
      certificates.push({
        der: asOctetString(inner),
        ...(bag.localKeyId === undefined ? {} : { localKeyId: bag.localKeyId }),
      })
    } else if (bag.bagId === OID.KEY_BAG) {
      privateKeyDer = bag.value.raw
      keyLocalId = bag.localKeyId
      friendlyName ??= bag.friendlyName
    } else if (bag.bagId === OID.SHROUDED_KEY_BAG) {
      // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
      const [algorithmNode, dataNode] = asSequence(bag.value)
      if (algorithmNode === undefined || dataNode === undefined) {
        throw new Pkcs12Error('malformed', 'Şifreli özel anahtar yapısı eksik.')
      }
      privateKeyDer = decryptPbe(algorithmNode, asOctetString(dataNode), password)
      keyLocalId = bag.localKeyId
      friendlyName ??= bag.friendlyName
    }
  }

  if (privateKeyDer === undefined) throw new Pkcs12Error('missing', 'Kapta özel anahtar yok.')
  if (certificates.length === 0) throw new Pkcs12Error('missing', 'Kapta sertifika yok.')

  let privateKey: KeyObject
  try {
    privateKey = createPrivateKey({ key: Buffer.from(privateKeyDer), format: 'der', type: 'pkcs8' })
  } catch (error) {
    throw new Pkcs12Error(
      'malformed',
      `Özel anahtar okunamadı: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  const parsed = certificates.map((entry) => ({
    ...entry,
    x509: new X509Certificate(Buffer.from(entry.der)),
  }))
  const leaf = selectLeafCertificate(parsed, keyLocalId, privateKey)

  const rest = parsed.filter((entry) => entry !== leaf)
  return {
    privateKey,
    certificate: leaf.der,
    chain: orderChain(leaf.x509, rest),
    ...(friendlyName === undefined ? {} : { friendlyName }),
  }
}

/** {@link selectLeafCertificate} girdisi. */
export interface CandidateCertificate {
  readonly der: Uint8Array
  readonly x509: X509Certificate
  readonly localKeyId?: string
}

/**
 * Kaptaki sertifikalardan özel anahtara ait olanı seçer.
 *
 * İki yol denenir, bu sırayla:
 * 1. `localKeyId` özniteliği — kap, anahtarla sertifikayı zaten
 *    eşleştirmişse en ucuz ve en kesin cevap budur.
 * 2. `checkPrivateKey` — öznitelik yoksa ya da yanlışsa, açık anahtar
 *    doğrudan karşılaştırılır.
 *
 * Yaygın sezgisel yol — "kimsenin düzenleyeni olmayan sertifika" — burada
 * KULLANILMIYOR. Çapraz imzalı zincirlerde iki sertifika da uç görünebilir
 * ve sezgi yanlış olanı seçer. Seçim ne olursa olsun sonunda `checkPrivateKey`
 * ile doğrulanıyor: yanlış bir sertifika sessizce geçemez, hata verir.
 *
 * @param candidates - Kaptaki sertifikalar
 * @param keyLocalId - Özel anahtarın `localKeyId` değeri, varsa
 * @param privateKey - Kaptan çıkan özel anahtar
 * @returns Anahtara ait sertifika
 * @throws {Pkcs12Error} Eşleşen sertifika yoksa
 */
export const selectLeafCertificate = <T extends CandidateCertificate>(
  candidates: readonly T[],
  keyLocalId: string | undefined,
  privateKey: KeyObject,
): T => {
  const leaf =
    candidates.find((entry) => keyLocalId !== undefined && entry.localKeyId === keyLocalId) ??
    candidates.find((entry) => entry.x509.checkPrivateKey(privateKey))
  if (leaf === undefined) {
    throw new Pkcs12Error('missing', 'Özel anahtarla eşleşen sertifika kapta bulunamadı.')
  }
  if (!leaf.x509.checkPrivateKey(privateKey)) {
    throw new Pkcs12Error(
      'malformed',
      'localKeyId ile işaretlenen sertifika özel anahtarla eşleşmiyor.',
    )
  }
  return leaf
}

/**
 * Kalan sertifikaları uçtan köke doğru sıralar.
 *
 * Her adımda "bir önceki sertifikayı imzalamış olan" aranır. Zincire
 * bağlanamayanlar atılmaz, sona eklenir — kapta ilgisiz bir sertifika olması
 * onu silmek için gerekçe değildir.
 */
const orderChain = (
  leaf: X509Certificate,
  rest: readonly { readonly der: Uint8Array; readonly x509: X509Certificate }[],
): readonly Uint8Array[] => {
  const remaining = [...rest]
  const ordered: Uint8Array[] = []
  let current = leaf
  for (;;) {
    const index = remaining.findIndex((entry) => {
      try {
        return current.checkIssued(entry.x509)
      } catch {
        return false
      }
    })
    if (index === -1) break
    const [next] = remaining.splice(index, 1)
    if (next === undefined) break
    ordered.push(next.der)
    current = next.x509
  }
  return [...ordered, ...remaining.map((entry) => entry.der)]
}

/** `ContentInfo` içindeki `data` oktetlerini verir; başka tür ise `undefined`. */
const contentInfoData = (node: DerNode): Uint8Array | undefined => {
  const parts = asSequence(node)
  const typeNode = parts[0]
  const contentNode = parts[1]
  if (typeNode === undefined || contentNode === undefined) return undefined
  if (asOid(typeNode) !== OID.DATA) return undefined
  const inner = contentNode.children[0]
  return inner === undefined ? undefined : asOctetString(inner)
}

/** Bir `ContentInfo`'yu (düz ya da şifreli) torbalara açar. */
const readSafeContents = (contentInfo: DerNode, password: string): readonly SafeBag[] => {
  const parts = asSequence(contentInfo)
  const typeNode = parts[0]
  const contentNode = parts[1]
  if (typeNode === undefined || contentNode === undefined) return []
  const type = asOid(typeNode)

  let safeContents: Uint8Array
  if (type === OID.DATA) {
    const inner = contentNode.children[0]
    if (inner === undefined) return []
    safeContents = asOctetString(inner)
  } else if (type === OID.ENCRYPTED_DATA) {
    const encryptedData = contentNode.children[0]
    if (encryptedData === undefined) return []
    // EncryptedData ::= SEQUENCE { version, encryptedContentInfo }
    const encryptedContentInfo = asSequence(encryptedData)[1]
    if (encryptedContentInfo === undefined) return []
    const fields = asSequence(encryptedContentInfo)
    const algorithmNode = fields[1]
    // encryptedContent [0] IMPLICIT OCTET STRING — örtük etiketli, içerik ham.
    const encrypted = findContext(fields, 0)
    if (algorithmNode === undefined || encrypted === undefined) return []
    safeContents = decryptPbe(algorithmNode, encrypted.content, password)
  } else {
    // secretBag ve benzeri türler bu pakette kullanılmıyor; sessizce atlanır.
    return []
  }

  return asSequence(decodeDer(safeContents)).map(readSafeBag)
}

/** Tek bir `SafeBag`'i okur ve özniteliklerini ayıklar. */
const readSafeBag = (node: DerNode): SafeBag => {
  const parts = asSequence(node)
  const bagIdNode = parts[0]
  const bagValueNode = parts[1]
  if (bagIdNode === undefined || bagValueNode === undefined) {
    throw new Pkcs12Error('malformed', 'SafeBag yapısı eksik.')
  }
  const value = bagValueNode.children[0]
  if (value === undefined) throw new Pkcs12Error('malformed', 'SafeBag içeriği boş.')

  let friendlyName: string | undefined
  let localKeyId: string | undefined
  const attributes = parts[2]
  if (attributes !== undefined) {
    for (const attribute of asSet(attributes)) {
      const fields = asSequence(attribute)
      const oidNode = fields[0]
      const valuesNode = fields[1]
      if (oidNode === undefined || valuesNode === undefined) continue
      const first = asSet(valuesNode)[0]
      if (first === undefined) continue
      const oid = asOid(oidNode)
      if (oid === OID.FRIENDLY_NAME) friendlyName = asString(first)
      else if (oid === OID.LOCAL_KEY_ID) localKeyId = toBase64(asOctetString(first))
    }
  }

  return {
    bagId: asOid(bagIdNode),
    value,
    ...(friendlyName === undefined ? {} : { friendlyName }),
    ...(localKeyId === undefined ? {} : { localKeyId }),
  }
}

/**
 * Kabın bütünlük etiketini doğrular.
 *
 * MAC, parolanın doğruluğunu içerik çözülmeden önce söyleyen tek işarettir.
 * Karşılaştırma sabit zamanda yapılır: bir bütünlük etiketini erken çıkışla
 * karşılaştırmak, doğru etiketi bayt bayt tahmin etmeye yol açar.
 */
const verifyMac = (macData: DerNode, authSafeContent: Uint8Array, password: string): void => {
  const parts = asSequence(macData)
  const digestInfo = parts[0]
  const saltNode = parts[1]
  if (digestInfo === undefined || saltNode === undefined) {
    throw new Pkcs12Error('malformed', 'MacData yapısı eksik.')
  }
  const digestParts = asSequence(digestInfo)
  const algorithmNode = digestParts[0]
  const digestNode = digestParts[1]
  if (algorithmNode === undefined || digestNode === undefined) {
    throw new Pkcs12Error('malformed', 'MacData özet yapısı eksik.')
  }

  const hashOid = asOid(asSequence(algorithmNode)[0] ?? algorithmNode)
  const hash = MAC_HASH[hashOid]
  if (hash === undefined) {
    throw new Pkcs12Error('unsupported', `Desteklenmeyen MAC özeti: ${hashOid}`)
  }

  const salt = asOctetString(saltNode)
  // `iterations` alanı DEFAULT 1'dir; yoksa kodlanmamış olabilir.
  const iterationsNode = parts[2]
  const iterations = iterationsNode === undefined ? 1 : Number(asInteger(iterationsNode))
  const expected = asOctetString(digestNode)

  for (const encoded of passwordEncodings(password)) {
    const key = pkcs12Kdf(encoded, salt, Pkcs12KeyType.MAC, iterations, expected.length, hash)
    const actual = new Uint8Array(
      createHmac(hash, Buffer.from(key)).update(Buffer.from(authSafeContent)).digest(),
    )
    if (timingSafeEqual(actual, expected)) return
  }

  throw new Pkcs12Error(
    'integrity',
    'Bütünlük doğrulaması başarısız — parola yanlış ya da dosya bozulmuş.',
  )
}
