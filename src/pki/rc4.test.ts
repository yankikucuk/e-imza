import { describe, expect, it } from 'vitest'

import { fromHex, toHex, utf8 } from '../core/bytes.js'

import { rc4 } from './rc4.js'

describe('RC4 bilinen vektörler', () => {
  /** Orijinal RC4 tanımıyla birlikte dolaşan, yaygın olarak alıntılanan üçlü. */
  const VECTORS: readonly (readonly [string, string, string])[] = [
    ['Key', 'Plaintext', 'bbf316e8d940af0ad3'],
    ['Wiki', 'pedia', '1021bf0420'],
    ['Secret', 'Attack at dawn', '45a01f645fc35b383552544b9bf5'],
  ]

  it('her vektörde beklenen akışı üretir', () => {
    for (const [key, plaintext, expected] of VECTORS) {
      expect(toHex(rc4(utf8(plaintext), utf8(key)))).toBe(expected)
    }
  })

  it('aynı işlem geri döndürür — akış şifresi simetriktir', () => {
    for (const [key, plaintext, expected] of VECTORS) {
      expect(new TextDecoder().decode(rc4(fromHex(expected), utf8(key)))).toBe(plaintext)
    }
  })

  it('uzunluk korunur, dolgu eklenmez', () => {
    for (let length = 0; length < 40; length += 7) {
      expect(rc4(new Uint8Array(length), utf8('k')).length).toBe(length)
    }
  })

  it('geçersiz anahtar uzunluğu reddedilir', () => {
    expect(() => rc4(new Uint8Array(4), new Uint8Array(0))).toThrow(RangeError)
    expect(() => rc4(new Uint8Array(4), new Uint8Array(257))).toThrow(RangeError)
  })
})
