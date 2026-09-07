import { describe, expect, it } from 'vitest'

import { fromUtf8, utf8 } from '../core/bytes.js'

import { buildIncrementalUpdate, serializePdfObject } from './incremental.js'
import { PdfReader, type PdfObject } from './object.js'

/**
 * PDF yazıcısı.
 *
 * Yazdığı dosyayı imza doğrulayan başka uygulamalar okuyacak; bu yüzden
 * her testin ölçüsü **gidiş-dönüş**: yazdığımız metin kendi
 * ayrıştırıcımızla okunduğunda aynı nesneyi vermeli.
 */

const write = (object: PdfObject): string => fromUtf8(serializePdfObject(object))
const roundTrip = (object: PdfObject): PdfObject =>
  new PdfReader(serializePdfObject(object)).readObject()

describe('nesne yazımı', () => {
  it('temel türler', () => {
    expect(write({ kind: 'null' })).toBe('null')
    expect(write({ kind: 'boolean', value: true })).toBe('true')
    expect(write({ kind: 'boolean', value: false })).toBe('false')
    expect(write({ kind: 'number', value: 42 })).toBe('42')
    expect(write({ kind: 'name', value: 'Type' })).toBe('/Type')
    expect(write({ kind: 'ref', number: 3, generation: 0 })).toBe('3 0 R')
  })

  /** Üstel gösterim PDF'te GEÇERSİZ; ondalık yazılmak zorunda. */
  it('ondalık sayılar üstel gösterime kaçmıyor', () => {
    expect(write({ kind: 'number', value: 0.5 })).toBe('0.5')
    expect(write({ kind: 'number', value: 0.0000001 })).not.toContain('e')
    expect(write({ kind: 'number', value: -3.25 })).toBe('-3.25')
  })

  /** Ad içindeki özel karakterler `#XX` ile kaçırılmak zorunda. */
  it('adlardaki özel karakterler kaçırılıyor', () => {
    expect(write({ kind: 'name', value: 'A B' })).toBe('/A#20B')
    expect(write({ kind: 'name', value: 'a/b' })).toBe('/a#2fb')
    expect(roundTrip({ kind: 'name', value: 'A B' })).toStrictEqual({
      kind: 'name',
      value: 'A B',
    })
  })

  /**
   * Parantez ve ters eğik çizgi kaçırılmazsa dize erken kapanır ve dosya
   * bozulur — imza gerekçesinde parantez bulunması yeterli.
   */
  it('dizelerdeki parantezler kaçırılıyor', () => {
    const object: PdfObject = { kind: 'string', value: utf8('a(b)c\\d'), hex: false }
    expect(write(object)).toBe('(a\\(b\\)c\\\\d)')
    const geri = roundTrip(object)
    expect(geri.kind === 'string' ? fromUtf8(geri.value) : '').toBe('a(b)c\\d')
  })

  it('onaltılık dize', () => {
    const object: PdfObject = {
      kind: 'string',
      value: new Uint8Array([0xfe, 0xff, 0x00]),
      hex: true,
    }
    expect(write(object)).toBe('<feff00>')
    const geri = roundTrip(object)
    expect(geri.kind === 'string' ? [...geri.value] : []).toStrictEqual([0xfe, 0xff, 0x00])
  })

  it('dizi ve sözlük gidip geliyor', () => {
    const object: PdfObject = {
      kind: 'array',
      items: [
        { kind: 'number', value: 1 },
        { kind: 'name', value: 'Ad' },
        { kind: 'ref', number: 2, generation: 0 },
      ],
    }
    expect(write(object)).toBe('[1 /Ad 2 0 R]')
    const geri = roundTrip(object)
    expect(geri.kind === 'array' ? geri.items.length : 0).toBe(3)
  })

  it('akış gidip geliyor', () => {
    const object: PdfObject = {
      kind: 'stream',
      entries: new Map([['Length', { kind: 'number', value: 3 }]]),
      raw: utf8('abc'),
    }
    const geri = roundTrip(object)
    expect(geri.kind).toBe('stream')
    expect(geri.kind === 'stream' ? fromUtf8(geri.raw) : '').toBe('abc')
  })
})

describe('artımlı güncelleme', () => {
  const original = utf8('%PDF-1.7\n1 0 obj\n<< >>\nendobj\nxref\n0 1\ntrailer\n<< >>\n%%EOF')

  it('özgün baytlar korunuyor ve yeni bölüm sonda', () => {
    const out = buildIncrementalUpdate({
      original,
      previousStartXref: 10,
      rootReference: 1,
      objects: [{ number: 2, body: utf8('<< /A 1 >>') }],
      size: 3,
    })
    expect(fromUtf8(out.subarray(0, original.length))).toBe(fromUtf8(original))
    const eklenen = fromUtf8(out.subarray(original.length))
    expect(eklenen).toContain('2 0 obj')
    expect(eklenen).toContain('/Prev 10')
    expect(eklenen).toContain('startxref')
    expect(eklenen.endsWith('%%EOF\n')).toBe(true)
  })

  /**
   * Bitişik olmayan nesne numaraları AYRI alt bölümlere yazılmak zorunda.
   * Tek blokta yazmak, aradaki güncellenmemiş nesneleri güncellenmiş
   * gösterirdi ve okuyucu yanlış konumlara giderdi.
   */
  it('bitişik olmayan numaralar ayrı alt bölümlere ayrılıyor', () => {
    const out = fromUtf8(
      buildIncrementalUpdate({
        original,
        previousStartXref: 10,
        rootReference: 1,
        objects: [
          { number: 2, body: utf8('<< >>') },
          { number: 3, body: utf8('<< >>') },
          { number: 9, body: utf8('<< >>') },
        ],
        size: 10,
      }),
    )
    expect(out).toContain('2 2\n')
    expect(out).toContain('9 1\n')
  })

  it('çapraz başvuru girdileri tam 20 bayt', () => {
    const out = fromUtf8(
      buildIncrementalUpdate({
        original,
        previousStartXref: 10,
        rootReference: 1,
        objects: [{ number: 2, body: utf8('<< >>') }],
        size: 3,
      }),
    )
    const satir = /\n(\d{10} 00000 n \n)/.exec(out)?.[1]
    expect(satir).toBeDefined()
    expect(satir).toHaveLength(20)
  })

  it('fragmana ek girdiler taşınıyor', () => {
    const out = fromUtf8(
      buildIncrementalUpdate({
        original,
        previousStartXref: 10,
        rootReference: 1,
        objects: [{ number: 2, body: utf8('<< >>') }],
        size: 3,
        extraTrailer: new Map([
          ['ID', { kind: 'array', items: [{ kind: 'string', value: utf8('x'), hex: true }] }],
        ]),
      }),
    )
    expect(out).toContain('/ID [<78>]')
  })

  /** Özgün dosya satır sonuyla bitmiyorsa yeni bölüm kendi satırında başlamalı. */
  it('satır sonu olmadan biten dosyaya ayraç ekleniyor', () => {
    const out = buildIncrementalUpdate({
      original: utf8('%PDF-1.7\n%%EOF'),
      previousStartXref: 0,
      rootReference: 1,
      objects: [{ number: 2, body: utf8('<< >>') }],
      size: 3,
    })
    expect(fromUtf8(out.subarray(14, 16))).toBe('\n2')
  })
})
