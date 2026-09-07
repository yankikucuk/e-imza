import { describe, expect, it } from 'vitest'

import { minimalPdf, pdfWithPredictor, pdfWithXrefStream } from '../../tests/pdf-fixture.js'
import { fromUtf8, utf8 } from '../core/bytes.js'

import { catalog, firstPage, getObject, readPdf, resolve } from './document.js'
import { dictEntry } from './object.js'

/**
 * PDF belge yapısı okuma.
 *
 * Üç yol da sınanıyor çünkü üçü de sahada var: klasik `xref` tablosu,
 * çapraz başvuru akışı, ve öngörücülü akış. Yanlış okunan bir tablo hata
 * VERMEZ — sessizce yanlış konumlar döndürür ve belge kökü bulunamaz.
 */

describe('çapraz başvuru biçimleri', () => {
  it('klasik xref tablosu', () => {
    const document = readPdf(minimalPdf())
    expect(document.size).toBe(4)
    expect(document.xref.size).toBe(3)
    expect(catalog(document).reference).toBe(1)
    expect(firstPage(document).reference).toBe(3)
  })

  it('çapraz başvuru akışı ve nesne akışı', () => {
    const document = readPdf(pdfWithXrefStream())
    expect(catalog(document).reference).toBe(1)
    expect(firstPage(document).reference).toBe(3)
    // Katalog bir nesne akışının İÇİNDE; çözülebiliyor olması o yolun
    // çalıştığını gösteriyor.
    expect(dictEntry(catalog(document).object, 'Type')).toStrictEqual({
      kind: 'name',
      value: 'Catalog',
    })
  })

  /**
   * Öngörücü geri alınmazsa tablo sessizce yanlış okunur. Bu testin
   * geçmesi, satır farklarının doğru toplandığını gösteriyor.
   */
  it('PNG öngörücülü çapraz başvuru akışı', () => {
    const document = readPdf(pdfWithPredictor())
    expect(catalog(document).reference).toBe(1)
    expect(firstPage(document).reference).toBe(3)
    expect(dictEntry(firstPage(document).object, 'MediaBox')).toBeDefined()
  })
})

describe('nesne çözümleme', () => {
  const document = readPdf(minimalPdf({ pages: 2 }))

  it('numarayla nesne alınıyor', () => {
    expect(dictEntry(getObject(document, 1) ?? { kind: 'null' }, 'Type')).toStrictEqual({
      kind: 'name',
      value: 'Catalog',
    })
  })

  it('olmayan nesne undefined dönüyor', () => {
    expect(getObject(document, 999)).toBeUndefined()
  })

  it('dolaylı başvuru çözülüyor', () => {
    const pages = dictEntry(catalog(document).object, 'Pages')
    expect(pages?.kind).toBe('ref')
    expect(dictEntry(resolve(document, pages) ?? { kind: 'null' }, 'Type')).toStrictEqual({
      kind: 'name',
      value: 'Pages',
    })
  })

  it('doğrudan nesne olduğu gibi dönüyor', () => {
    const direct = { kind: 'number' as const, value: 5 }
    expect(resolve(document, direct)).toBe(direct)
    expect(resolve(document, undefined)).toBeUndefined()
  })

  it('çok sayfalı ağaçta ilk sayfa bulunuyor', () => {
    expect(firstPage(document).reference).toBe(3)
  })
})

describe('bozuk ve desteklenmeyen girdi', () => {
  it('PDF başlığı yoksa reddediliyor', () => {
    expect(() => readPdf(utf8('bu bir PDF değil'))).toThrow(/%PDF-/)
  })

  it('startxref yoksa reddediliyor', () => {
    expect(() => readPdf(utf8('%PDF-1.7\n%%EOF\n'))).toThrow(/startxref/)
  })

  it('startxref değeri okunamıyorsa reddediliyor', () => {
    expect(() => readPdf(utf8('%PDF-1.7\nstartxref\nxx\n%%EOF\n'))).toThrow(/startxref/)
  })

  /**
   * Şifreli PDF'e imza eklemek belgeyi çözmeyi gerektirir; sessizce
   * denemek bozuk bir dosya üretirdi.
   */
  it('şifreli PDF açıkça reddediliyor', () => {
    const bozuk = fromUtf8(minimalPdf()).replace(
      '/Size 4 /Root 1 0 R',
      '/Size 4 /Root 1 0 R /Encrypt 9 0 R',
    )
    expect(() => readPdf(utf8(bozuk))).toThrow(/şifreli/)
  })

  it('/Root dolaylı değilse katalog çözülemiyor', () => {
    const bozuk = fromUtf8(minimalPdf()).replace('/Root 1 0 R', '/Root << >>   ')
    expect(() => catalog(readPdf(utf8(bozuk)))).toThrow(/Root/)
  })

  it('çapraz başvuru göstermediği konumda hata veriyor', () => {
    const bozuk = fromUtf8(minimalPdf()).replace(/startxref\n\d+/, 'startxref\n9')
    expect(() => readPdf(utf8(bozuk))).toThrow()
  })
})
