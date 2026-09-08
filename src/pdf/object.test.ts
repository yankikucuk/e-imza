import { describe, expect, it } from 'vitest'

import { fromUtf8, toHex, utf8 } from '../core/bytes.js'
import { PdfSyntaxError } from '../core/errors.js'

import {
  dictEntry,
  indexOfSequence,
  lastIndexOfSequence,
  PdfReader,
  type PdfObject,
} from './object.js'

/**
 * PDF nesne ayrıştırıcısı.
 *
 * Bu bir **girdi ayrıştırıcısıdır**: okuduğu dosya karşı taraftan gelir ve
 * yapısını gönderen belirler. İmza doğrulaması onun ne okuduğuna bağlı —
 * yanlış okunan bir `/ByteRange`, imzanın kapsamadığı bir bölgeyi
 * kapsıyormuş gibi gösterir.
 */

const read = (text: string): PdfObject => new PdfReader(utf8(text)).readObject()

describe('temel türler', () => {
  it('sayılar', () => {
    expect(read('42')).toStrictEqual({ kind: 'number', value: 42 })
    expect(read('-3.14')).toStrictEqual({ kind: 'number', value: -3.14 })
    expect(read('+7')).toStrictEqual({ kind: 'number', value: 7 })
    expect(read('.5')).toStrictEqual({ kind: 'number', value: 0.5 })
  })

  it('mantıksal değerler ve null', () => {
    expect(read('true')).toStrictEqual({ kind: 'boolean', value: true })
    expect(read('false')).toStrictEqual({ kind: 'boolean', value: false })
    expect(read('null')).toStrictEqual({ kind: 'null' })
  })

  it('adlar', () => {
    expect(read('/Type')).toStrictEqual({ kind: 'name', value: 'Type' })
    // `#XX` kaçışı: `/A#20B` bir boşluk içeren addır.
    expect(read('/A#20B')).toStrictEqual({ kind: 'name', value: 'A B' })
    expect(read('/')).toStrictEqual({ kind: 'name', value: '' })
  })

  /**
   * Dolaylı başvuru `N G R` biçiminde ve ancak İLERİYE BAKARAK sayıdan
   * ayırt edilebiliyor: `1 0 R` bir başvuru, `1 0` iki sayı. Ayrımı
   * kaçırmak dizinin uzunluğunu değiştirir.
   */
  it('dolaylı başvurular sayılardan ayırt ediliyor', () => {
    expect(read('12 0 R')).toStrictEqual({ kind: 'ref', number: 12, generation: 0 })
    const reader = new PdfReader(utf8('12 0'))
    expect(reader.readObject()).toStrictEqual({ kind: 'number', value: 12 })
    expect(reader.readObject()).toStrictEqual({ kind: 'number', value: 0 })
  })
})

describe('dizeler', () => {
  const text = (object: PdfObject): string =>
    object.kind === 'string' ? fromUtf8(object.value) : ''

  it('düz dize', () => {
    expect(text(read('(merhaba)'))).toBe('merhaba')
  })

  /** Dengeli parantezler kaçırılmadan yazılabilir; sayaç tutulmalı. */
  it('iç içe parantezler', () => {
    expect(text(read('(a (b) c)'))).toBe('a (b) c')
    expect(text(read('(a ((b)) c)'))).toBe('a ((b)) c')
  })

  it('ters eğik çizgi kaçışları', () => {
    expect(text(read('(a\\nb)'))).toBe('a\nb')
    expect(text(read('(a\\tb)'))).toBe('a\tb')
    expect(text(read('(a\\(b\\))'))).toBe('a(b)')
    expect(text(read('(a\\\\b)'))).toBe('a\\b')
  })

  /** Sekizlik kaçış: en fazla üç basamak. */
  it('sekizlik kaçışlar', () => {
    const object = read('(\\101\\102)')
    expect(text(object)).toBe('AB')
    const kisa = read('(\\7)')
    expect(kisa.kind === 'string' ? kisa.value[0] : -1).toBe(7)
  })

  it('onaltılık dize', () => {
    const object = read('<48656C6C6F>')
    expect(text(object)).toBe('Hello')
    expect(object.kind === 'string' ? object.hex : false).toBe(true)
  })

  /** Tek basamak kalırsa sona sıfır eklenir (PDF 32000-1 §7.3.4.3). */
  it('tek basamaklı onaltılık dize sıfırla tamamlanıyor', () => {
    const object = read('<4A5>')
    expect(object.kind === 'string' ? toHex(object.value) : '').toBe('4a50')
  })

  it('onaltılık dizedeki boşluklar yok sayılıyor', () => {
    expect(text(read('<48 65 6C 6C 6F>'))).toBe('Hello')
  })
})

describe('bileşik türler', () => {
  it('dizi', () => {
    const object = read('[1 /Ad (metin) 2 0 R]')
    expect(object.kind).toBe('array')
    if (object.kind !== 'array') return
    expect(object.items).toHaveLength(4)
    expect(object.items[3]).toStrictEqual({ kind: 'ref', number: 2, generation: 0 })
  })

  it('boş dizi ve boş sözlük', () => {
    expect(read('[]')).toStrictEqual({ kind: 'array', items: [] })
    const bos = read('<<>>')
    expect(bos.kind).toBe('dict')
  })

  it('sözlük ve iç içe sözlük', () => {
    const object = read('<< /Type /Page /Resources << /Font 5 0 R >> >>')
    expect(dictEntry(object, 'Type')).toStrictEqual({ kind: 'name', value: 'Page' })
    const resources = dictEntry(object, 'Resources')
    expect(resources).toBeDefined()
    if (resources === undefined) return
    expect(dictEntry(resources, 'Font')).toStrictEqual({
      kind: 'ref',
      number: 5,
      generation: 0,
    })
  })

  it('akış — /Length ile', () => {
    const object = read('<< /Length 5 >>\nstream\nABCDE\nendstream')
    expect(object.kind).toBe('stream')
    if (object.kind !== 'stream') return
    expect(fromUtf8(object.raw)).toBe('ABCDE')
  })

  /**
   * `/Length` dolaylı olabilir; o zaman `endstream` aranır ve öncesindeki
   * satır sonu akışın parçası sayılmaz.
   */
  it('akış — /Length dolaylıysa endstream aranıyor', () => {
    const object = read('<< /Length 9 0 R >>\nstream\nABCDE\nendstream')
    expect(object.kind).toBe('stream')
    if (object.kind !== 'stream') return
    expect(fromUtf8(object.raw)).toBe('ABCDE')
  })

  it('yorumlar atlanıyor', () => {
    expect(read('% bu bir yorum\n42')).toStrictEqual({ kind: 'number', value: 42 })
    const object = read('<< % yorum\n/A 1 >>')
    expect(dictEntry(object, 'A')).toStrictEqual({ kind: 'number', value: 1 })
  })
})

describe('bozuk girdi', () => {
  const bad: readonly (readonly [string, string])[] = [
    ['kapanmamış dizi', '[1 2'],
    ['kapanmamış sözlük', '<< /A 1'],
    ['sözlük anahtarı ad değil', '<< 1 2 >>'],
    ['tanınmayan simge', 'foo'],
    ['boş girdi', ''],
  ]
  for (const [name, text] of bad) {
    it(`reddediliyor: ${name}`, () => {
      expect(() => read(text)).toThrow(PdfSyntaxError)
    })
  }
})

describe('bayt arama', () => {
  const haystack = utf8('abcXYZabcXYZ')
  it('ileri arama', () => {
    expect(indexOfSequence(haystack, utf8('XYZ'))).toBe(3)
    expect(indexOfSequence(haystack, utf8('XYZ'), 4)).toBe(9)
    expect(indexOfSequence(haystack, utf8('yok'))).toBe(-1)
  })

  /** `startxref` her zaman SONDAN aranır: dosyada birden çok olabilir. */
  it('geriye arama', () => {
    expect(lastIndexOfSequence(haystack, utf8('XYZ'))).toBe(9)
    expect(lastIndexOfSequence(haystack, utf8('yok'))).toBe(-1)
  })
})

describe('dictEntry', () => {
  it('sözlük olmayan nesnede undefined dönüyor', () => {
    expect(dictEntry({ kind: 'number', value: 1 }, 'A')).toBeUndefined()
  })
})

/**
 * İç içelik sınırı olmadan, saldırganın hazırladığı bir belge ayrıştırıcının
 * çağrı yığınını tüketiyordu: `RangeError: Maximum call stack size exceeded`.
 * Sınır, bunu yakalanabilir bir sözdizimi hatasına çeviriyor.
 */
describe('iç içelik sınırı', () => {
  const oku = (metin: string): PdfObject => new PdfReader(utf8(metin)).readObject()

  it('makul derinlikte dizi ve sözlük okunuyor', () => {
    expect(oku('['.repeat(150) + ']'.repeat(150)).kind).toBe('array')
    expect(oku('<< /A '.repeat(150) + '1' + ' >>'.repeat(150)).kind).toBe('dict')
  })

  it('aşırı derin dizi yığını taşırmak yerine hata veriyor', () => {
    expect(() => oku('['.repeat(50_000) + ']'.repeat(50_000))).toThrow(/iç içe/)
  })

  it('aşırı derin sözlük yığını taşırmak yerine hata veriyor', () => {
    expect(() => oku('<< /A '.repeat(50_000) + '1' + ' >>'.repeat(50_000))).toThrow(/iç içe/)
  })

  it('yan yana derin yapılar sınırı tüketmiyor', () => {
    const bir = '['.repeat(150) + ']'.repeat(150)
    expect(oku(`[${bir} ${bir} ${bir}]`).kind).toBe('array')
  })
})
