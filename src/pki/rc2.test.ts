import { describe, expect, it } from 'vitest'

import { fromHex, toHex } from '../core/bytes.js'

import { expandRc2Key, rc2CbcDecrypt, rc2DecryptBlock, rc2EncryptBlock } from './rc2.js'

/**
 * RFC 2268 §5'teki resmî test vektörleri.
 *
 * Bu vektörler `PITABLE`'ı, anahtar genişletmeyi ve on altı turun tamamını
 * aynı anda sınar: tablodaki tek bir bayt yanlış olsa hiçbiri tutmaz. Saf
 * JavaScript'te yazılmış bir blok şifresi için gereken doğrulama tam olarak
 * budur — "çalışıyor gibi görünüyor" yeterli değildir.
 */
const RFC_2268_VECTORS: readonly {
  readonly key: string
  readonly effectiveBits: number
  readonly plaintext: string
  readonly ciphertext: string
}[] = [
  {
    key: '0000000000000000',
    effectiveBits: 63,
    plaintext: '0000000000000000',
    ciphertext: 'ebb773f993278eff',
  },
  {
    key: 'ffffffffffffffff',
    effectiveBits: 64,
    plaintext: 'ffffffffffffffff',
    ciphertext: '278b27e42e2f0d49',
  },
  {
    key: '3000000000000000',
    effectiveBits: 64,
    plaintext: '1000000000000001',
    ciphertext: '30649edf9be7d2c2',
  },
  { key: '88', effectiveBits: 64, plaintext: '0000000000000000', ciphertext: '61a8a244adacccf0' },
  {
    key: '88bca90e90875a',
    effectiveBits: 64,
    plaintext: '0000000000000000',
    ciphertext: '6ccf4308974c267f',
  },
  {
    key: '88bca90e90875a7f0f79c384627bafb2',
    effectiveBits: 64,
    plaintext: '0000000000000000',
    ciphertext: '1a807d272bbe5db1',
  },
  {
    key: '88bca90e90875a7f0f79c384627bafb2',
    effectiveBits: 128,
    plaintext: '0000000000000000',
    ciphertext: '2269552ab0f85ca6',
  },
  {
    key: '88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e',
    effectiveBits: 129,
    plaintext: '0000000000000000',
    ciphertext: '5b78d3a43dfff1f1',
  },
]

describe('RFC 2268 test vektörleri', () => {
  it('şifreleme yönü her vektörde tutar', () => {
    for (const vector of RFC_2268_VECTORS) {
      const roundKeys = expandRc2Key(fromHex(vector.key), vector.effectiveBits)
      expect(toHex(rc2EncryptBlock(fromHex(vector.plaintext), roundKeys))).toBe(vector.ciphertext)
    }
  })

  it('çözme yönü şifrelemenin tam tersidir', () => {
    for (const vector of RFC_2268_VECTORS) {
      const roundKeys = expandRc2Key(fromHex(vector.key), vector.effectiveBits)
      expect(toHex(rc2DecryptBlock(fromHex(vector.ciphertext), roundKeys))).toBe(vector.plaintext)
    }
  })
})

describe('anahtar genişletme sınırları', () => {
  it('geçersiz anahtar uzunluğu reddedilir', () => {
    expect(() => expandRc2Key(new Uint8Array(0), 64)).toThrow(RangeError)
    expect(() => expandRc2Key(new Uint8Array(129), 64)).toThrow(RangeError)
  })

  it('geçersiz etkin uzunluk reddedilir', () => {
    expect(() => expandRc2Key(fromHex('88'), 0)).toThrow(RangeError)
    expect(() => expandRc2Key(fromHex('88'), 1025)).toThrow(RangeError)
  })

  /**
   * PKCS#12'de fiilen görülen iki uzunluk. 40 bit, eski araçların
   * `pbeWithSHAAnd40BitRC2-CBC` seçimi; kütüphanenin var oluş nedeni bu.
   */
  it('40 ve 128 bit etkin uzunluk farklı anahtar üretir', () => {
    const key = fromHex('0102030405')
    expect(toHex(new Uint8Array(expandRc2Key(key, 40).buffer))).not.toBe(
      toHex(new Uint8Array(expandRc2Key(key, 128).buffer)),
    )
  })
})

describe('CBC kipi', () => {
  const encryptCbc = (
    plaintext: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    effectiveBits: number,
  ): Uint8Array => {
    const padding = 8 - (plaintext.length % 8)
    const padded = new Uint8Array(plaintext.length + padding)
    padded.set(plaintext)
    padded.fill(padding, plaintext.length)
    const roundKeys = expandRc2Key(key, effectiveBits)
    const out = new Uint8Array(padded.length)
    let previous = iv
    for (let offset = 0; offset < padded.length; offset += 8) {
      const block = padded.subarray(offset, offset + 8).slice()
      for (let i = 0; i < 8; i += 1) block[i] = (block[i] ?? 0) ^ (previous[i] ?? 0)
      const encrypted = rc2EncryptBlock(block, roundKeys)
      out.set(encrypted, offset)
      previous = encrypted
    }
    return out
  }

  it('CBC gidip gelir ve dolgu kaldırılır', () => {
    const key = fromHex('0102030405')
    const iv = fromHex('a1a2a3a4a5a6a7a8')
    for (const text of ['', 'a', 'sekiz ba', 'tam sekiz bayttan uzun bir metin']) {
      const plaintext = new TextEncoder().encode(text)
      const encrypted = encryptCbc(plaintext, key, iv, 40)
      expect(toHex(rc2CbcDecrypt(encrypted, key, iv, 40))).toBe(toHex(plaintext))
    }
  })

  it('bozuk uzunluk ve başlangıç vektörü reddedilir', () => {
    const key = fromHex('0102030405')
    expect(() => rc2CbcDecrypt(fromHex('0011'), key, fromHex('a1a2a3a4a5a6a7a8'), 40)).toThrow(
      /8'in katı/,
    )
    expect(() => rc2CbcDecrypt(fromHex('0011223344556677'), key, fromHex('a1a2'), 40)).toThrow(
      /8 bayt olmalı/,
    )
  })

  it('yanlış şifre dolgu hatasıyla ayırt edilir', () => {
    const iv = fromHex('a1a2a3a4a5a6a7a8')
    const encrypted = encryptCbc(new TextEncoder().encode('gizli'), fromHex('0102030405'), iv, 40)
    expect(() => rc2CbcDecrypt(encrypted, fromHex('0908070605'), iv, 40)).toThrow(/şifre yanlış/)
  })

  /**
   * Üçüncü bağımsız doğrulama: LibreSSL'in kendi RC2 uygulaması. RFC
   * vektörleri tek blok üzerindedir; bu test zincirlemeyi, dolguyu ve
   * `rc2-40-cbc` ile `rc2-64-cbc` arasındaki etkin uzunluk farkını sınar —
   * yani PKCS#12'de fiilen karşılaşılan yolu.
   *
   * Beklenen çıktılar şu komutla üretildi:
   * `openssl enc -rc2-40-cbc -K 0102030405 -iv a1a2a3a4a5a6a7a8`
   */
  it('LibreSSL referans şifreli metinlerini çözer', () => {
    const iv = fromHex('a1a2a3a4a5a6a7a8')
    const message = 'gizli mesaj 16b'

    expect(
      new TextDecoder().decode(
        rc2CbcDecrypt(fromHex('bb4ff954218839a76172b4f080561c60'), fromHex('0102030405'), iv, 40),
      ),
    ).toBe(message)

    expect(
      new TextDecoder().decode(
        rc2CbcDecrypt(
          fromHex('969b2ca5c22b312b56a7fd954e6b8222'),
          fromHex('0102030405060708'),
          iv,
          64,
        ),
      ),
    ).toBe(message)
  })

  it('blok boyutu dışındaki girdi reddedilir', () => {
    const roundKeys = expandRc2Key(fromHex('88'), 64)
    expect(() => rc2EncryptBlock(fromHex('0011'), roundKeys)).toThrow(/8 bayt olmalı/)
  })
})
