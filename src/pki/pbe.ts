import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto'

import { asInteger, asOctetString, asOid, asSequence, type DerNode } from '../asn1/der.js'
import { concat } from '../core/bytes.js'
import { Pkcs12Error } from '../core/errors.js'

import { rc2CbcDecrypt } from './rc2.js'
import { rc4 } from './rc4.js'

/**
 * Parola tabanlı şifrelemenin çözme tarafı — PKCS#12 kaplarının içeriği
 * bununla açılır.
 *
 * İki nesil bir arada desteklenir:
 * - **PBES1** (RFC 7292 App. C) — eski Java, Windows ve OpenSSL 1.x
 *   araçlarının ürettiği kaplar. RC2 ve RC4 varyantları Node'un
 *   kriptografisinde artık yok; bu paketin kendi uygulamalarına düşer.
 * - **PBES2** (RFC 8018) — PBKDF2 + AES ya da 3DES. OpenSSL 3'ün
 *   varsayılanı.
 */

/** PKCS#12 anahtar türetiminde kullanılan özet fonksiyonları. */
export type Pkcs12Hash = 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512'

/** Özet çıktı uzunlukları (bayt). */
const HASH_OUTPUT: Readonly<Record<Pkcs12Hash, number>> = {
  sha1: 20,
  sha224: 28,
  sha256: 32,
  sha384: 48,
  sha512: 64,
}

/** Özet iç blok uzunlukları (bayt) — KDF'nin `v` parametresi. */
const HASH_BLOCK: Readonly<Record<Pkcs12Hash, number>> = {
  sha1: 64,
  sha224: 64,
  sha256: 64,
  sha384: 128,
  sha512: 128,
}

/** KDF'nin ürettiği malzemenin türü (RFC 7292 App. B.3). */
export const Pkcs12KeyType = {
  /** Şifreleme anahtarı. */
  KEY: 1,
  /** Başlangıç vektörü. */
  IV: 2,
  /** Bütünlük (MAC) anahtarı. */
  MAC: 3,
} as const

/**
 * Parolayı PKCS#12'nin beklediği biçime çevirir: UTF-16BE artı iki baytlık
 * sonlandırıcı.
 *
 * @param password - Kullanıcı parolası
 * @returns BMPString kodlaması
 */
export const encodePkcs12Password = (password: string): Uint8Array => {
  const out = new Uint8Array(password.length * 2 + 2)
  for (let i = 0; i < password.length; i += 1) {
    const code = password.charCodeAt(i)
    out[i * 2] = (code >> 8) & 0xff
    out[i * 2 + 1] = code & 0xff
  }
  return out
}

/**
 * Boş parolanın iki olası kodlaması.
 *
 * RFC 7292 boş parolayı iki baytlık sonlandırıcı olarak tanımlar, ama
 * OpenSSL geçmişte "parola yok" durumunu sıfır uzunluklu dizeyle işledi ve
 * o davranışla üretilmiş kaplar sahada mevcut. Hangisinin doğru olduğu
 * dosyaya göre değişir; ikisini de denemek, kullanıcıyı "şifre boş ama
 * açılmıyor" durumunda bırakmamanın tek yolu.
 *
 * @param password - Kullanıcı parolası
 * @returns Denenmesi gereken kodlamalar, en olası olan başta
 */
export const passwordEncodings = (password: string): readonly Uint8Array[] =>
  password === '' ? [new Uint8Array([0, 0]), new Uint8Array(0)] : [encodePkcs12Password(password)]

/**
 * PKCS#12 anahtar türetme işlevi (RFC 7292 App. B.2).
 *
 * PBKDF2 değildir ve onun yerine geçmez; PKCS#12'ye özgü, `D`, `S`, `P`
 * bloklarını modüler toplamayla ilerleten ayrı bir yapıdır.
 *
 * @param password - {@link encodePkcs12Password} çıktısı
 * @param salt - Tuz
 * @param id - {@link Pkcs12KeyType} değerlerinden biri
 * @param iterations - Yineleme sayısı
 * @param length - İstenen bayt sayısı
 * @param hash - Özet fonksiyonu
 * @returns Türetilmiş anahtar malzemesi
 */
export const pkcs12Kdf = (
  password: Uint8Array,
  salt: Uint8Array,
  id: number,
  iterations: number,
  length: number,
  hash: Pkcs12Hash = 'sha1',
): Uint8Array => {
  const v = HASH_BLOCK[hash]
  const u = HASH_OUTPUT[hash]

  const D = new Uint8Array(v).fill(id)
  const expand = (source: Uint8Array): Uint8Array => {
    if (source.length === 0) return new Uint8Array(0)
    const size = v * Math.ceil(source.length / v)
    const out = new Uint8Array(size)
    for (let i = 0; i < size; i += 1) out[i] = source[i % source.length] ?? 0
    return out
  }
  const S = expand(salt)
  const P = expand(password)
  const I = concat(S, P)

  const blocks = Math.ceil(length / u)
  const pieces: Uint8Array[] = []

  for (let i = 0; i < blocks; i += 1) {
    let A = new Uint8Array(createHash(hash).update(D).update(I).digest())
    for (let round = 1; round < iterations; round += 1) {
      A = new Uint8Array(createHash(hash).update(A).digest())
    }
    pieces.push(A)
    if (i === blocks - 1) break

    // B, A'nın v bayta kadar tekrarıdır; I'nın her v baytlık dilimi
    // (B + 1) ile modüler olarak toplanır.
    const B = new Uint8Array(v)
    for (let n = 0; n < v; n += 1) B[n] = A[n % A.length] ?? 0
    for (let start = 0; start < I.length; start += v) {
      let carry = 1
      for (let n = v - 1; n >= 0; n -= 1) {
        const sum = (I[start + n] ?? 0) + (B[n] ?? 0) + carry
        I[start + n] = sum & 0xff
        carry = sum >> 8
      }
    }
  }

  return concat(...pieces).subarray(0, length)
}

/* ── Algoritma kimlikleri ─────────────────────────────────────────────── */

/** PBES1 varyantları — RFC 7292 App. C. */
interface Pbes1Scheme {
  readonly cipher: 'rc2' | 'rc4' | '3des' | '2des'
  readonly keyLength: number
  readonly ivLength: number
  /** RC2 için etkin anahtar uzunluğu (bit). */
  readonly effectiveBits?: number
}

const PBES1: Readonly<Record<string, Pbes1Scheme>> = {
  '1.2.840.113549.1.12.1.1': { cipher: 'rc4', keyLength: 16, ivLength: 0 },
  '1.2.840.113549.1.12.1.2': { cipher: 'rc4', keyLength: 5, ivLength: 0 },
  '1.2.840.113549.1.12.1.3': { cipher: '3des', keyLength: 24, ivLength: 8 },
  '1.2.840.113549.1.12.1.4': { cipher: '2des', keyLength: 16, ivLength: 8 },
  '1.2.840.113549.1.12.1.5': { cipher: 'rc2', keyLength: 16, ivLength: 8, effectiveBits: 128 },
  '1.2.840.113549.1.12.1.6': { cipher: 'rc2', keyLength: 5, ivLength: 8, effectiveBits: 40 },
}

/** İnsan tarafından okunabilir adlar — hata mesajlarında kullanılır. */
const PBES1_NAMES: Readonly<Record<string, string>> = {
  '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
  '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
  '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.4': 'pbeWithSHAAnd2-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.5': 'pbeWithSHAAnd128BitRC2-CBC',
  '1.2.840.113549.1.12.1.6': 'pbeWithSHAAnd40BitRC2-CBC',
}

const OID_PBES2 = '1.2.840.113549.1.5.13'
const OID_PBKDF2 = '1.2.840.113549.1.5.12'

/** PBES2'nin kullandığı simetrik şifreler. */
const PBES2_CIPHERS: Readonly<
  Record<string, { readonly name: string; readonly keyLength: number }>
> = {
  '2.16.840.1.101.3.4.1.2': { name: 'aes-128-cbc', keyLength: 16 },
  '2.16.840.1.101.3.4.1.22': { name: 'aes-192-cbc', keyLength: 24 },
  '2.16.840.1.101.3.4.1.42': { name: 'aes-256-cbc', keyLength: 32 },
  '1.2.840.113549.3.7': { name: 'des-ede3-cbc', keyLength: 24 },
}

/** PBKDF2 sözde rastgele işlevleri. */
const PBKDF2_PRF: Readonly<Record<string, Pkcs12Hash>> = {
  '1.2.840.113549.2.7': 'sha1',
  '1.2.840.113549.2.8': 'sha224',
  '1.2.840.113549.2.9': 'sha256',
  '1.2.840.113549.2.10': 'sha384',
  '1.2.840.113549.2.11': 'sha512',
}

/**
 * PKCS#12'de geçen `AlgorithmIdentifier`'a göre şifreli veriyi çözer.
 *
 * @param algorithm - `AlgorithmIdentifier` düğümü (`SEQUENCE { oid, params }`)
 * @param ciphertext - Şifreli veri
 * @param password - Kullanıcı parolası
 * @returns Çözülmüş düz metin
 * @throws {Pkcs12Error} Algoritma desteklenmiyorsa ya da parola yanlışsa
 */
export const decryptPbe = (
  algorithm: DerNode,
  ciphertext: Uint8Array,
  password: string,
): Uint8Array => {
  const parts = asSequence(algorithm)
  const oid = asOid(parts[0] ?? algorithm)
  const parameters = parts[1]

  const attempts = passwordEncodings(password)
  let lastError: unknown
  for (const encoded of attempts) {
    try {
      return oid === OID_PBES2
        ? decryptPbes2(parameters, ciphertext, password)
        : decryptPbes1(oid, parameters, ciphertext, encoded)
    } catch (error) {
      lastError = error
    }
  }
  if (lastError instanceof Pkcs12Error) throw lastError
  throw new Pkcs12Error(
    'password',
    'İçerik çözülemedi — parola yanlış olabilir. ' +
      (lastError instanceof Error ? lastError.message : String(lastError)),
  )
}

/** PBES1 ailesi (RFC 7292 App. C) — PKCS#12'ye özgü KDF kullanır. */
const decryptPbes1 = (
  oid: string,
  parameters: DerNode | undefined,
  ciphertext: Uint8Array,
  password: Uint8Array,
): Uint8Array => {
  const scheme = PBES1[oid]
  if (scheme === undefined) {
    throw new Pkcs12Error('unsupported', `Desteklenmeyen şifreleme algoritması: ${oid}`)
  }
  if (parameters === undefined) {
    throw new Pkcs12Error('malformed', `${PBES1_NAMES[oid] ?? oid} parametresiz geldi.`)
  }

  const [saltNode, iterationsNode] = asSequence(parameters)
  if (saltNode === undefined || iterationsNode === undefined) {
    throw new Pkcs12Error('malformed', 'PBES1 parametreleri eksik (tuz ya da yineleme sayısı).')
  }
  const salt = asOctetString(saltNode)
  const iterations = Number(asInteger(iterationsNode))

  const key = pkcs12Kdf(password, salt, Pkcs12KeyType.KEY, iterations, scheme.keyLength)

  if (scheme.cipher === 'rc4') {
    // Akış şifresi: dolgu yok, uzunluk korunur.
    return rc4(ciphertext, key)
  }

  const iv = pkcs12Kdf(password, salt, Pkcs12KeyType.IV, iterations, scheme.ivLength)

  if (scheme.cipher === 'rc2') {
    return rc2CbcDecrypt(ciphertext, key, iv, scheme.effectiveBits ?? 128)
  }

  const cipherName = scheme.cipher === '3des' ? 'des-ede3-cbc' : 'des-ede-cbc'
  return nodeCbcDecrypt(cipherName, key, iv, ciphertext)
}

/** PBES2 (RFC 8018) — PBKDF2 ile türetip AES/3DES ile çözer. */
const decryptPbes2 = (
  parameters: DerNode | undefined,
  ciphertext: Uint8Array,
  password: string,
): Uint8Array => {
  if (parameters === undefined) throw new Pkcs12Error('malformed', 'PBES2 parametresiz geldi.')
  const [kdfNode, encryptionNode] = asSequence(parameters)
  if (kdfNode === undefined || encryptionNode === undefined) {
    throw new Pkcs12Error('malformed', 'PBES2 parametreleri eksik.')
  }

  const kdfParts = asSequence(kdfNode)
  if (asOid(kdfParts[0] ?? kdfNode) !== OID_PBKDF2) {
    throw new Pkcs12Error('unsupported', 'PBES2 yalnızca PBKDF2 ile destekleniyor.')
  }
  const kdfParameters = asSequence(kdfParts[1] ?? kdfNode)
  const salt = asOctetString(kdfParameters[0] ?? kdfNode)
  const iterations = Number(asInteger(kdfParameters[1] ?? kdfNode))

  // İsteğe bağlı `keyLength` ve `prf`; ikisi de atlanmış olabilir.
  let explicitKeyLength: number | undefined
  let prf: Pkcs12Hash = 'sha1'
  for (const node of kdfParameters.slice(2)) {
    if (node.tagClass === 'universal' && node.tagNumber === 2) {
      explicitKeyLength = Number(asInteger(node))
    } else if (node.tagClass === 'universal' && node.tagNumber === 16) {
      const prfOid = asOid(asSequence(node)[0] ?? node)
      const resolved = PBKDF2_PRF[prfOid]
      if (resolved === undefined) {
        throw new Pkcs12Error('unsupported', `Desteklenmeyen PBKDF2 PRF: ${prfOid}`)
      }
      prf = resolved
    }
  }

  const encryptionParts = asSequence(encryptionNode)
  const cipherOid = asOid(encryptionParts[0] ?? encryptionNode)
  const cipher = PBES2_CIPHERS[cipherOid]
  if (cipher === undefined) {
    throw new Pkcs12Error('unsupported', `Desteklenmeyen PBES2 şifresi: ${cipherOid}`)
  }
  const iv = asOctetString(encryptionParts[1] ?? encryptionNode)

  const key = new Uint8Array(
    pbkdf2Sync(password, salt, iterations, explicitKeyLength ?? cipher.keyLength, prf),
  )
  return nodeCbcDecrypt(cipher.name, key, iv, ciphertext)
}

/** `node:crypto` üzerinden CBC çözme; dolgu hatası parola hatasına çevrilir. */
const nodeCbcDecrypt = (
  cipherName: string,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array => {
  try {
    const decipher = createDecipheriv(cipherName, key, iv)
    return new Uint8Array(
      Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]),
    )
  } catch (error) {
    throw new Pkcs12Error(
      'password',
      `${cipherName} çözümü başarısız — parola yanlış olabilir. ` +
        (error instanceof Error ? error.message : String(error)),
    )
  }
}
