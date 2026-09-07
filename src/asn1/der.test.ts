import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import { fromHex, toHex } from '../core/bytes.js'
import { DerParseError } from '../core/errors.js'

import {
  asBitString,
  asInteger,
  asOctetString,
  asOid,
  asSequence,
  asSet,
  asString,
  asTime,
  decodeDer,
  derBitString,
  derGeneralizedTime,
  derInteger,
  derNull,
  derOctetString,
  derOid,
  derSequence,
  derSetOf,
  derUtf8String,
  DerTag,
  findContext,
} from './der.js'

/**
 * Bağımsız oracle: OpenSSL'in kendi ASN.1 çözümleyicisi. Kendi kodlayıcımızın
 * ürettiği baytları OpenSSL okuyabiliyorsa, kodlama yalnızca "kendi
 * çözümleyicimizle uyumlu" değil, gerçekten DER'dir.
 */
const hasOpenssl = ((): boolean => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

describe('OID kodlaması', () => {
  /**
   * Bilinen vektörler. `sha256WithRSAEncryption` her X.509 sertifikasında
   * geçtiği için baytları ezbere doğrulanabilir bir referanstır.
   */
  const VECTORS: readonly (readonly [string, string])[] = [
    ['1.2.840.113549.1.1.11', '06092a864886f70d01010b'], // sha256WithRSAEncryption
    ['1.2.840.113549.1.1.1', '06092a864886f70d010101'], // rsaEncryption
    ['1.2.840.10045.2.1', '06072a8648ce3d0201'], // id-ecPublicKey
    ['2.5.4.3', '0603550403'], // commonName
    ['1.3.14.3.2.26', '05052b0e03021a'.replace(/^05/, '06')], // sha1
    ['2.16.792.1.61.0.1.5070.3.2.1', '060c608618013d0001a74e030201'], // TR P3 imza politikası
  ]

  it("bilinen OID'leri doğru kodlar", () => {
    for (const [oid, hex] of VECTORS) expect(toHex(derOid(oid))).toBe(hex)
  })

  it('kodlama ve çözümleme birbirinin tersidir', () => {
    for (const [oid] of VECTORS) expect(asOid(decodeDer(derOid(oid)))).toBe(oid)
  })

  it('çok baytlı bileşenleri taşır', () => {
    // 113549 tek bir bileşende dört yedilik gruba yayılır.
    expect(asOid(decodeDer(derOid('1.2.999999999.1')))).toBe('1.2.999999999.1')
  })

  it('geçersiz gösterimi reddeder', () => {
    expect(() => derOid('1')).toThrow(DerParseError)
    expect(() => derOid('1.a')).toThrow(DerParseError)
  })

  /**
   * Yukarıdaki vektörler elle yazıldı ve elle yazmak hata kaldırır — nitekim
   * ilk denemede TR politika OID'i yanlış yazılmıştı. Bu test, tablonun
   * tamamını OpenSSL'e ayrıca kodlatıp karşılaştırır: bundan sonra elle
   * yazılmış yanlış bir vektör sessiz kalamaz.
   */
  it.skipIf(!hasOpenssl)('vektör tablosu OpenSSL ile birebir eşleşir', () => {
    // `openssl asn1parse -genstr` çıktıyı yalnızca dosyaya yazabiliyor;
    // `-out -` boş döner. Bu yüzden geçici bir dosya kullanılıyor.
    const file = join(mkdtempSync(join(tmpdir(), 'e-imza-oid-')), 'oid.der')
    try {
      for (const [oid, hex] of VECTORS) {
        execFileSync('openssl', ['asn1parse', '-genstr', `OID:${oid}`, '-out', file, '-noout'])
        expect(toHex(new Uint8Array(readFileSync(file)))).toBe(hex)
      }
    } finally {
      rmSync(file, { force: true })
    }
  })
})

describe('INTEGER', () => {
  it('pozitif, negatif ve sıfır değerler gidip gelir', () => {
    for (const value of [0n, 1n, 127n, 128n, 255n, 256n, -1n, -128n, -129n, -256n]) {
      expect(asInteger(decodeDer(derInteger(value)))).toBe(value)
    }
  })

  it('üst biti 1 olan pozitif sayıya dolgu sıfırı ekler', () => {
    // 0x80 doğrudan yazılsa negatif okunurdu; DER başa 0x00 koyar.
    expect(toHex(derInteger(128n))).toBe('02020080')
    expect(toHex(derInteger(127n))).toBe('02017f')
  })

  it('20 baytlık sertifika seri numarasını kayıpsız taşır', () => {
    // `xadesjs#52`: seri numarası hex dize olarak yazılınca dış doğrulayıcılar
    // reddediyordu. Doğru gösterimin ön koşulu doğru tip: bigint.
    const serial = 0x00f1e2d3c4b5a69788796a5b4c3d2e1f00112233n
    expect(asInteger(decodeDer(derInteger(serial)))).toBe(serial)
  })
})

describe('temel türler', () => {
  it('OCTET STRING gidip gelir', () => {
    const payload = fromHex('deadbeef00ff')
    expect(toHex(asOctetString(decodeDer(derOctetString(payload))))).toBe('deadbeef00ff')
  })

  it('BIT STRING dolgu baytını yönetir', () => {
    const payload = fromHex('a1b2c3')
    expect(toHex(asBitString(decodeDer(derBitString(payload))))).toBe('a1b2c3')
  })

  it('sıfırdan farklı dolgu biti reddedilir', () => {
    // 03 03 04 a1 b2 — 4 kullanılmayan bit. Anahtar/imza yapılarında olmaz.
    expect(() => asBitString(decodeDer(fromHex('030304a1b2')))).toThrow(/dolgu biti/)
  })

  it('NULL boş içerikle kodlanır', () => {
    expect(toHex(derNull())).toBe('0500')
  })

  it('UTF8String Türkçe karakterleri taşır', () => {
    expect(asString(decodeDer(derUtf8String('Şirket Ünvanı Ğ İ ı')))).toBe('Şirket Ünvanı Ğ İ ı')
  })

  it('BMPString UTF-16BE olarak okunur', () => {
    // PKCS#12 dostu ad (friendlyName) BMPString ile yazılır.
    const node = decodeDer(fromHex('1e0800540065007300740073'.replace('0800', '0a00')))
    expect(asString(node)).toBe('Tests')
  })
})

describe('zaman', () => {
  it('UTCTime iki haneli yılı RFC 5280 kuralıyla çözer', () => {
    // "49" → 2049, "50" → 1950.
    const utc = (text: string): Date =>
      asTime(decodeDer(new Uint8Array([DerTag.UTC_TIME, text.length, ...Buffer.from(text)])))
    expect(utc('490101000000Z').getUTCFullYear()).toBe(2049)
    expect(utc('500101000000Z').getUTCFullYear()).toBe(1950)
  })

  it('GeneralizedTime gidip gelir', () => {
    const when = new Date(Date.UTC(2026, 8, 7, 12, 34, 56))
    expect(asTime(decodeDer(derGeneralizedTime(when))).toISOString()).toBe(when.toISOString())
  })

  it('bozuk zaman değeri reddedilir', () => {
    expect(() => asTime(decodeDer(derUtf8String('dün')))).toThrow(DerParseError)
  })
})

describe('kurgusal türler', () => {
  it('SEQUENCE alt düğümleri sırayla verir', () => {
    const encoded = derSequence(derInteger(1n), derUtf8String('a'), derNull())
    const items = asSequence(decodeDer(encoded))
    expect(items).toHaveLength(3)
    expect(asInteger(items[0]!)).toBe(1n)
    expect(asString(items[1]!)).toBe('a')
  })

  /**
   * DER, `SET OF` öğelerinin kodlanmış hâllerine göre sıralanmasını ŞART
   * koşar. CMS `signedAttrs` bir `SET OF`'tur ve imza tam olarak bu kodlama
   * üzerinden hesaplanır; sıralamayı atlayan uygulama yalnızca kendi
   * doğrulayıcısıyla çalışır.
   */
  it('SET OF öğeleri kodlanmış baytlara göre sıralar', () => {
    const encoded = derSetOf(derInteger(3n), derInteger(1n), derInteger(2n))
    const items = asSet(decodeDer(encoded))
    expect(items.map((item) => asInteger(item))).toStrictEqual([1n, 2n, 3n])
  })

  it('SET OF sıralaması girdi sırasından bağımsızdır', () => {
    const a = derSetOf(derUtf8String('zeta'), derUtf8String('alfa'))
    const b = derSetOf(derUtf8String('alfa'), derUtf8String('zeta'))
    expect(toHex(a)).toBe(toHex(b))
  })

  it('bağlama özgü etiket bulunur', () => {
    const encoded = derSequence(derInteger(1n), fromHex('a003020105'))
    const found = findContext(asSequence(decodeDer(encoded)), 0)
    expect(found).toBeDefined()
    expect(asInteger(found!.children[0]!)).toBe(5n)
  })
})

describe('ham baytların korunması', () => {
  /**
   * `raw`, imza doğrulamanın temelidir: sertifika özeti ve CMS imzalı
   * öznitelikler KAYNAKTAKİ baytlar üzerinden hesaplanır. Düğümü yeniden
   * kodlayıp özetlemek, kaynağın DER'e tam uymadığı durumlarda farklı
   * bir özet üretir ve imza tutmaz.
   */
  it('düğümün raw alanı kaynağın birebir dilimidir', () => {
    const inner = derInteger(42n)
    const encoded = derSequence(derNull(), inner)
    const items = asSequence(decodeDer(encoded))
    expect(toHex(items[1]!.raw)).toBe(toHex(inner))
  })
})

describe('bozuk girdi', () => {
  it('belirsiz uzunluk reddedilir', () => {
    // 30 80 … BER'de geçerli, DER'de değil.
    expect(() => decodeDer(fromHex('308002010500'))).toThrow(/Belirsiz uzunluk/)
  })

  it('kaynağı aşan uzunluk reddedilir', () => {
    expect(() => decodeDer(fromHex('3010020101'))).toThrow(/aşıyor/)
  })

  it('değerden sonraki artık baytlar reddedilir', () => {
    expect(() => decodeDer(fromHex('050000'))).toThrow(/artık bayt/)
  })

  it('boş girdi reddedilir', () => {
    expect(() => decodeDer(new Uint8Array(0))).toThrow(DerParseError)
  })

  it('beklenmeyen etiket açık hata verir', () => {
    expect(() => asSequence(decodeDer(derNull()))).toThrow(/SEQUENCE bekleniyordu/)
    expect(() => asInteger(decodeDer(derNull()))).toThrow(/INTEGER bekleniyordu/)
  })
})

describe.skipIf(!hasOpenssl)('OpenSSL ile çapraz doğrulama', () => {
  const parse = (bytes: Uint8Array): string =>
    execFileSync('openssl', ['asn1parse', '-inform', 'DER'], {
      input: Buffer.from(bytes),
      encoding: 'utf8',
    })

  it("ürettiğimiz SEQUENCE'i OpenSSL okur", () => {
    const encoded = derSequence(
      derOid('1.2.840.113549.1.1.11'),
      derInteger(-129n),
      derUtf8String('Ünvan'),
    )
    const output = parse(encoded)
    expect(output).toContain('sha256WithRSAEncryption')
    // OpenSSL INTEGER'ları ONALTILIK yazar: -129 = -0x81 → ":-81".
    // İki'ye tümleyen kodlamamız 02 02 FF 7F üretir ve OpenSSL onu -129 okur.
    expect(output).toContain(':-81')
    expect(output).toContain('Ünvan')
  })

  it("ürettiğimiz OID'i OpenSSL aynı adla çözer", () => {
    expect(parse(derSequence(derOid('1.2.840.10045.2.1')))).toContain('id-ecPublicKey')
  })
})
