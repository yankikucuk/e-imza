import { describe, expect, it } from 'vitest'

import {
  concat,
  fromBase64,
  fromHex,
  fromUtf8,
  timingSafeEqual,
  toBase64,
  toHex,
  utf8,
  wrapBase64,
} from './bytes.js'

describe('birleştirme', () => {
  it('parçaları sırayla ekler', () => {
    expect(toHex(concat(fromHex('0102'), fromHex(''), fromHex('0304')))).toBe('01020304')
  })

  it('parçasız çağrı boş dizi verir', () => {
    expect(concat()).toHaveLength(0)
  })
})

describe('onaltılık dönüşüm', () => {
  it('gidip gelir', () => {
    for (const hex of ['', '00', 'ff', 'deadbeef', '000102030405060708090a0b0c0d0e0f']) {
      expect(toHex(fromHex(hex))).toBe(hex)
    }
  })

  it('büyük harfli girdiyi kabul eder, küçük harfli üretir', () => {
    expect(toHex(fromHex('DEADBEEF'))).toBe('deadbeef')
  })

  it('tek uzunluk reddedilir', () => {
    expect(() => fromHex('abc')).toThrow(/çift olmalı/)
  })

  it('onaltılık olmayan karakter reddedilir', () => {
    expect(() => fromHex('zz')).toThrow(/Onaltılık olmayan/)
    expect(() => fromHex('0g')).toThrow(/Onaltılık olmayan/)
  })
})

describe('base64', () => {
  it('gidip gelir', () => {
    const bytes = fromHex('000102fdfeff')
    expect(toHex(fromBase64(toBase64(bytes)))).toBe('000102fdfeff')
  })

  it('boşluk ve satır sonu yok sayılır', () => {
    // PEM ve XML içindeki base64 neredeyse her zaman satırlara bölünmüş gelir.
    expect(toHex(fromBase64('3q2\n+7w  =\t'))).toBe(toHex(fromBase64('3q2+7w==')))
  })

  it('satır sarma istenen genişlikte yapılır', () => {
    const long = 'A'.repeat(200)
    const wrapped = wrapBase64(long, 64)
    expect(wrapped.split('\n').every((line) => line.length <= 64)).toBe(true)
    expect(wrapped.replace(/\n/g, '')).toBe(long)
  })

  it('sarma kapatılabilir ve kısa dizeyi bölmez', () => {
    expect(wrapBase64('kısa', 0)).toBe('kısa')
    expect(wrapBase64('kısa', -1)).toBe('kısa')
    expect(wrapBase64('kısa', 64)).toBe('kısa')
  })
})

describe('UTF-8', () => {
  it('Türkçe karakterler kayıpsız gidip gelir', () => {
    const text = 'ĞÜŞİÖÇ ğüşıöç — em tire ve € işareti'
    expect(fromUtf8(utf8(text))).toBe(text)
  })
})

describe('sabit zamanlı karşılaştırma', () => {
  it('aynı içerik için doğru döner', () => {
    expect(timingSafeEqual(fromHex('a1b2c3'), fromHex('a1b2c3'))).toBe(true)
  })

  it('tek bit farkı yakalar', () => {
    expect(timingSafeEqual(fromHex('a1b2c3'), fromHex('a1b2c2'))).toBe(false)
    // İlk bayttaki fark da son baytaki fark da aynı şekilde yakalanmalı.
    expect(timingSafeEqual(fromHex('a1b2c3'), fromHex('a0b2c3'))).toBe(false)
  })

  it('farklı uzunluk için yanlış döner', () => {
    expect(timingSafeEqual(fromHex('a1b2'), fromHex('a1b2c3'))).toBe(false)
  })

  it('boş diziler eşittir', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
  })
})
