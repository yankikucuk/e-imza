import { describe, expect, it } from 'vitest'

import { decodeDer, derInteger, derNull, derOctetString, derOid, derSequence } from '../asn1/der.js'
import { fromHex, toHex, utf8 } from '../core/bytes.js'
import { Pkcs12Error } from '../core/errors.js'

import {
  decryptPbe,
  encodePkcs12Password,
  passwordEncodings,
  pkcs12Kdf,
  Pkcs12KeyType,
} from './pbe.js'

describe('parola kodlaması', () => {
  it('BMPString: UTF-16BE artı iki baytlık sonlandırıcı', () => {
    expect(toHex(encodePkcs12Password('ab'))).toBe('00610062' + '0000')
    expect(toHex(encodePkcs12Password(''))).toBe('0000')
  })

  it('Türkçe karakterler UTF-16BE olarak yazılır', () => {
    expect(toHex(encodePkcs12Password('Ş'))).toBe('015e0000')
  })

  /**
   * RFC 7292 boş parolayı iki baytlık sonlandırıcı olarak tanımlar; OpenSSL
   * geçmişte sıfır uzunluklu dize kullandı ve o davranışla üretilmiş kaplar
   * sahada mevcut. İkisi de denenmezse kullanıcı "şifre boş ama açılmıyor"
   * durumunda kalır.
   */
  it('boş parola için iki kodlama da denenir', () => {
    const encodings = passwordEncodings('')
    expect(encodings).toHaveLength(2)
    expect(toHex(encodings[0]!)).toBe('0000')
    expect(encodings[1]).toHaveLength(0)
  })

  it('dolu parola için tek kodlama denenir', () => {
    expect(passwordEncodings('x')).toHaveLength(1)
  })
})

describe('PKCS#12 anahtar türetimi', () => {
  const password = encodePkcs12Password('parola')
  const salt = fromHex('0102030405060708')

  it('istenen uzunlukta malzeme üretir', () => {
    for (const length of [1, 5, 16, 20, 24, 32, 48, 64]) {
      expect(pkcs12Kdf(password, salt, Pkcs12KeyType.KEY, 100, length)).toHaveLength(length)
    }
  })

  /**
   * Aynı parola ve tuzdan anahtar, başlangıç vektörü ve MAC anahtarı
   * TÜRETİLİR; üçü farklı olmalıdır. `id` parametresi karıştırılırsa
   * şifreleme anahtarı başlangıç vektörüyle aynı olur ve kap sessizce
   * zayıflar.
   */
  it('anahtar, IV ve MAC farklı malzeme üretir', () => {
    const key = toHex(pkcs12Kdf(password, salt, Pkcs12KeyType.KEY, 100, 24))
    const iv = toHex(pkcs12Kdf(password, salt, Pkcs12KeyType.IV, 100, 24))
    const mac = toHex(pkcs12Kdf(password, salt, Pkcs12KeyType.MAC, 100, 24))
    expect(new Set([key, iv, mac]).size).toBe(3)
  })

  it('yineleme sayısı sonucu değiştirir', () => {
    expect(toHex(pkcs12Kdf(password, salt, 1, 1, 20))).not.toBe(
      toHex(pkcs12Kdf(password, salt, 1, 2, 20)),
    )
  })

  it('özet fonksiyonu sonucu değiştirir', () => {
    expect(toHex(pkcs12Kdf(password, salt, 1, 100, 32, 'sha1'))).not.toBe(
      toHex(pkcs12Kdf(password, salt, 1, 100, 32, 'sha256')),
    )
  })

  it('blok uzunluğunu aşan istekte üretim döngüsü çalışır', () => {
    // SHA-1 çıktısı 20 bayt; 64 bayt istemek dört tur demektir ve turlar
    // arası `I` güncellemesi devreye girer.
    const long = pkcs12Kdf(password, salt, 1, 10, 64, 'sha1')
    expect(long).toHaveLength(64)
    expect(toHex(long.subarray(0, 20))).toBe(toHex(pkcs12Kdf(password, salt, 1, 10, 20, 'sha1')))
  })

  it('boş tuz kabul edilir', () => {
    expect(pkcs12Kdf(password, new Uint8Array(0), 1, 10, 16)).toHaveLength(16)
  })
})

describe('desteklenmeyen algoritmalar', () => {
  const algorithm = (oid: string, parameters?: Uint8Array): ReturnType<typeof decodeDer> =>
    decodeDer(derSequence(derOid(oid), parameters ?? derNull()))

  it("tanınmayan şifreleme OID'i açıkça reddedilir", () => {
    expect(() => decryptPbe(algorithm('1.2.3.4'), fromHex('00'), 'x')).toThrow(Pkcs12Error)
    expect(() => decryptPbe(algorithm('1.2.3.4'), fromHex('00'), 'x')).toThrow(
      /Desteklenmeyen şifreleme algoritması/,
    )
  })

  it('PBES1 parametresiz gelirse reddedilir', () => {
    const node = decodeDer(derSequence(derOid('1.2.840.113549.1.12.1.6')))
    expect(() => decryptPbe(node, fromHex('00'), 'x')).toThrow(/parametresiz/)
  })

  it('PBES1 parametreleri eksikse reddedilir', () => {
    const node = algorithm('1.2.840.113549.1.12.1.6', derSequence(derOctetString(fromHex('0102'))))
    expect(() => decryptPbe(node, fromHex('00'), 'x')).toThrow(/parametreleri eksik/)
  })

  it('PBES2 parametresiz gelirse reddedilir', () => {
    const node = decodeDer(derSequence(derOid('1.2.840.113549.1.5.13')))
    expect(() => decryptPbe(node, fromHex('00'), 'x')).toThrow(/parametresiz/)
  })

  it('PBES2 yalnızca PBKDF2 ile çalışır', () => {
    const node = algorithm(
      '1.2.840.113549.1.5.13',
      derSequence(
        derSequence(derOid('1.2.3.4'), derSequence(derOctetString(fromHex('01')), derInteger(1n))),
        derSequence(derOid('2.16.840.1.101.3.4.1.42'), derOctetString(fromHex('00'.repeat(16)))),
      ),
    )
    expect(() => decryptPbe(node, fromHex('00'.repeat(16)), 'x')).toThrow(/yalnızca PBKDF2/)
  })

  it('desteklenmeyen PBES2 şifresi reddedilir', () => {
    const node = algorithm(
      '1.2.840.113549.1.5.13',
      derSequence(
        derSequence(
          derOid('1.2.840.113549.1.5.12'),
          derSequence(derOctetString(fromHex('01020304')), derInteger(100n)),
        ),
        derSequence(derOid('1.2.3.4'), derOctetString(fromHex('00'.repeat(16)))),
      ),
    )
    expect(() => decryptPbe(node, fromHex('00'.repeat(16)), 'x')).toThrow(/PBES2 şifresi/)
  })

  it("desteklenmeyen PBKDF2 PRF'i reddedilir", () => {
    const node = algorithm(
      '1.2.840.113549.1.5.13',
      derSequence(
        derSequence(
          derOid('1.2.840.113549.1.5.12'),
          derSequence(
            derOctetString(fromHex('01020304')),
            derInteger(100n),
            derSequence(derOid('1.2.3.4'), derNull()),
          ),
        ),
        derSequence(derOid('2.16.840.1.101.3.4.1.42'), derOctetString(fromHex('00'.repeat(16)))),
      ),
    )
    expect(() => decryptPbe(node, fromHex('00'.repeat(16)), 'x')).toThrow(/PBKDF2 PRF/)
  })

  it('yanlış parolayla çözüm parola hatası verir', () => {
    // Gerçek bir PBES2 yapısı, ama şifreli veri rastgele: çözüm dolguda düşer.
    const node = algorithm(
      '1.2.840.113549.1.5.13',
      derSequence(
        derSequence(
          derOid('1.2.840.113549.1.5.12'),
          derSequence(derOctetString(fromHex('01020304')), derInteger(100n)),
        ),
        derSequence(derOid('2.16.840.1.101.3.4.1.42'), derOctetString(fromHex('00'.repeat(16)))),
      ),
    )
    expect(() => decryptPbe(node, utf8('xxxxxxxxxxxxxxxx'), 'yanlış')).toThrow(Pkcs12Error)
  })
})
