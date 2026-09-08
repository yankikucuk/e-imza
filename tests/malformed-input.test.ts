import { describe, expect, it } from 'vitest'

import { cadesVerify } from '../src/cades/verify.js'
import { utf8 } from '../src/core/bytes.js'
import { EImzaError } from '../src/core/errors.js'
import { padesVerify } from '../src/pades/verify.js'
import { readPdf } from '../src/pdf/document.js'
import { readCertificate } from '../src/pki/certificate.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { verifyTimestampToken } from '../src/pki/tsp.js'
import { verify } from '../src/verify.js'
import { parseXml } from '../src/xml/parse.js'
import { readZip } from '../src/zip/archive.js'

/**
 * Bozuk girdi.
 *
 * `EImzaError` ağacının tek sözü var: kütüphanenin fırlattığı HER hata bu
 * kökten gelir, böylece çağıran "girdi bozuk" ile "kodda bug var" ayrımını
 * yapabilir. İmza doğrulayan bir kütüphanede bu ayrım kritik — ikisi
 * karışırsa geçersiz bir imza sessizce yutulabilir.
 *
 * Buradaki girdilerin hepsi düşmanca: kesilmiş, uzunluğu yalan söyleyen,
 * aşırı derin ya da tamamen rastgele. Hiçbiri `RangeError` ya da
 * `TypeError` ile düşmemeli, hiçbiri asılı kalmamalı.
 */

/** Yinelenebilir olması için sözde rastgele baytlar. */
const noise = (length: number, seed: number): Uint8Array => {
  const out = new Uint8Array(length)
  let state = seed >>> 0
  for (let i = 0; i < length; i += 1) {
    state = (state * 1664525 + 1013904223) >>> 0
    out[i] = state >>> 24
  }
  return out
}

const der: readonly (readonly [string, Uint8Array])[] = [
  ['boş', new Uint8Array()],
  ['yalnızca etiket', Uint8Array.from([0x30])],
  ['uzunluk var, içerik yok', Uint8Array.from([0x30, 0x7f])],
  ['4 GB uzunluk', Uint8Array.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])],
  ['kapanmayan belirsiz uzunluk', Uint8Array.from([0x30, 0x80, 0x02, 0x01, 0x01])],
  ['rastgele 1 KB', noise(1024, 1)],
]

const xml: readonly (readonly [string, string])[] = [
  ['boş', ''],
  ['kapanmamış etiket', '<a'],
  ['eşleşmeyen etiket', '<a></b>'],
  ['DOCTYPE', '<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'],
  ['milyar kahkaha', '<!DOCTYPE l [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]><l>&b;</l>'],
  ['aşırı derin', '<a>'.repeat(20_000) + '</a>'.repeat(20_000)],
  ['bağlanmamış ön ek', '<x:a/>'],
  ['rastgele metin', new TextDecoder().decode(noise(4096, 3))],
]

const pdf: readonly (readonly [string, Uint8Array])[] = [
  ['boş', new Uint8Array()],
  ['yalnızca başlık', utf8('%PDF-1.7\n')],
  ['startxref dosya dışını gösteriyor', utf8('%PDF-1.7\ntrailer<<>>\nstartxref\n999999\n%%EOF')],
  ['startxref negatif', utf8('%PDF-1.7\ntrailer<<>>\nstartxref\n-5\n%%EOF')],
  [
    '/Length yalan söylüyor',
    utf8('%PDF-1.7\n1 0 obj\n<< /Length 999999 >>\nstream\nx\nendstream\nendobj\ntrailer<<>>\n'),
  ],
  [
    'aşırı derin dizi',
    utf8(`%PDF-1.7\n1 0 obj\n${'['.repeat(50_000)}${']'.repeat(50_000)}\nendobj\ntrailer<<>>\n`),
  ],
  ['rastgele 8 KB', noise(8192, 4)],
]

/** Girdiyi verir ve hatanın kütüphaneye ait olduğunu doğrular. */
const kutuphaneHatasi = (calistir: () => unknown): void => {
  try {
    calistir()
  } catch (error) {
    expect(error).toBeInstanceOf(EImzaError)
  }
}

describe('bozuk girdi kütüphane hatası veriyor', () => {
  it.each(der)('DER: %s', (_ad, girdi) => {
    kutuphaneHatasi(() => readCertificate(girdi))
    kutuphaneHatasi(() => verifyTimestampToken(girdi, { data: Uint8Array.from([1]) }))
    kutuphaneHatasi(() => cadesVerify(girdi, { data: Uint8Array.from([1]) }))
    kutuphaneHatasi(() => loadPkcs12(girdi, 'parola'))
  })

  it.each(xml)('XML: %s', (_ad, girdi) => {
    kutuphaneHatasi(() => parseXml(girdi))
    kutuphaneHatasi(() => verify(girdi))
  })

  it.each(pdf)('PDF: %s', (_ad, girdi) => {
    kutuphaneHatasi(() => readPdf(girdi))
    kutuphaneHatasi(() => padesVerify(girdi))
    kutuphaneHatasi(() => readZip(girdi))
  })
})
