import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { ASIC_MIME_TYPE, createAsic, readAsic } from '../src/asic/container.js'
import { cadesSign } from '../src/cades/sign.js'
import { cadesVerify } from '../src/cades/verify.js'
import { fromUtf8, toHex, utf8 } from '../src/core/bytes.js'
import { SigningError, VerificationError } from '../src/core/errors.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { createZip, peekFirstEntry, readZip } from '../src/zip/archive.js'
import { crc32 } from '../src/zip/crc32.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * ASiC ve altındaki ZIP katmanı.
 *
 * Bağımsız oracle: **`unzip`**. Ürettiğimiz arşivi Info-ZIP okuyabiliyorsa,
 * yerel başlıklar, merkezî dizin ve sağlamaların hepsi doğru demektir —
 * kendi okuyucumuzla test etmek bunların hiçbirini göstermez.
 */

const directory = mkdtempSync(join(tmpdir(), 'e-imza-asic-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

const hasUnzip = ((): boolean => {
  try {
    execFileSync('unzip', ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

let counter = 0
/** Arşivi diske yazıp `unzip` komutunu çalıştırır. */
const unzip = (archive: Uint8Array, args: readonly string[]): string => {
  counter += 1
  const file = join(directory, `arsiv-${String(counter)}.zip`)
  writeFileSync(file, archive)
  return execFileSync('unzip', [...args, file], { encoding: 'utf8' })
}

describe('CRC-32', () => {
  /** Yaygın olarak alıntılanan vektörler. */
  it('bilinen değerler', () => {
    expect(crc32(utf8('')).toString(16)).toBe('0')
    expect(crc32(utf8('a')).toString(16)).toBe('e8b7be43')
    expect(crc32(utf8('123456789')).toString(16)).toBe('cbf43926')
    expect(crc32(utf8('The quick brown fox jumps over the lazy dog')).toString(16)).toBe('414fa339')
  })
})

describe('ZIP katmanı', () => {
  const entries = [
    { name: 'mimetype', data: utf8('application/vnd.etsi.asic-s+zip'), stored: true },
    { name: 'fatura.xml', data: utf8('<Invoice>Ç Ş Ğ</Invoice>') },
    { name: 'META-INF/signature.p7s', data: new Uint8Array([1, 2, 3, 4, 5]) },
  ]

  it('yazıp okumak gidip geliyor', () => {
    const okunan = readZip(createZip(entries))
    expect(okunan).toHaveLength(3)
    expect(okunan.map((entry) => entry.name)).toStrictEqual([
      'mimetype',
      'fatura.xml',
      'META-INF/signature.p7s',
    ])
    expect(fromUtf8(okunan[1]?.data ?? new Uint8Array())).toBe('<Invoice>Ç Ş Ğ</Invoice>')
    expect(toHex(okunan[2]?.data ?? new Uint8Array())).toBe('0102030405')
  })

  it('sıkıştırılmamış girdi öyle kalıyor', () => {
    const okunan = readZip(createZip(entries))
    expect(okunan[0]?.stored).toBe(true)
    expect(okunan[1]?.stored).toBe(false)
  })

  it('boş dosya ve büyük dosya', () => {
    const buyuk = new Uint8Array(200_000).fill(0x41)
    const okunan = readZip(
      createZip([
        { name: 'bos.txt', data: new Uint8Array(0) },
        { name: 'buyuk.bin', data: buyuk },
      ]),
    )
    expect(okunan[0]?.data).toHaveLength(0)
    expect(okunan[1]?.data).toHaveLength(200_000)
  })

  /**
   * `mimetype` ilk ve sıkıştırılmamış olduğu için ZIP açılmadan okunabiliyor.
   * ASiC'in tür tespiti tamamen buna dayanıyor.
   */
  it('ilk girdi ZIP açılmadan okunabiliyor', () => {
    const ilk = peekFirstEntry(createZip(entries))
    expect(ilk?.name).toBe('mimetype')
    expect(fromUtf8(ilk?.data ?? new Uint8Array())).toBe('application/vnd.etsi.asic-s+zip')
  })

  it('sıkıştırılmış ilk girdi gözle okunamıyor', () => {
    const arsiv = createZip([{ name: 'mimetype', data: utf8('x'.repeat(200)) }])
    expect(peekFirstEntry(arsiv)).toBeUndefined()
  })

  /**
   * Asıl kanıt: Info-ZIP arşivimizi okuyabiliyorsa yerel başlıklar,
   * merkezî dizin ve CRC değerlerinin hepsi doğru demektir.
   */
  it.skipIf(!hasUnzip)('unzip arşivimizi sağlam buluyor', () => {
    const cikti = unzip(createZip(entries), ['-t'])
    expect(cikti).toContain('No errors detected')
  })

  it.skipIf(!hasUnzip)('unzip girdileri listeliyor', () => {
    const cikti = unzip(createZip(entries), ['-l'])
    expect(cikti).toContain('mimetype')
    expect(cikti).toContain('META-INF/signature.p7s')
  })

  it.skipIf(!hasUnzip)('unzip içeriği doğru açıyor', () => {
    const cikti = unzip(createZip(entries), ['-p'])
    expect(cikti).toContain('<Invoice>Ç Ş Ğ</Invoice>')
  })

  describe('merkezî dizin ile yerel başlık çeliştiğinde', () => {
    /**
     * Yerel başlıktaki ad ve ek alan uzunlukları, merkezî dizindekinden
     * FARKLI olabilir — ZIP biçimi bunu yasaklamıyor. Verinin nerede
     * başladığını yerel başlık söyler; merkezî dizindeki uzunlukları
     * kullanan bir okuyucu yanlış konumdan okur ve **hata vermez**,
     * sessizce yanlış içerik döndürür.
     *
     * Ölçüldü: bu test olmadan, yerel uzunluklar yerine merkezî
     * uzunlukları kullanan bir mutasyon hiçbir testi düşürmüyordu — çünkü
     * kendi yazdığımız arşivlerde ikisi hep aynı.
     */
    const u16 = (value: number): number[] => [value & 0xff, (value >>> 8) & 0xff]
    const u32 = (value: number): number[] => [
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 24) & 0xff,
    ]

    /** Yerel başlığında ek alan olan, merkezî dizininde olmayan arşiv. */
    const craft = (): Uint8Array => {
      const name = [...utf8('veri.txt')]
      const data = [...utf8('DOGRU')]
      const extra = [0x55, 0x54, 0x01, 0x00] // dört baytlık sahte ek alan
      const checksum = crc32(utf8('DOGRU'))

      const local = [
        ...u32(0x04034b50),
        ...u16(20),
        ...u16(0),
        ...u16(0), // sıkıştırılmamış
        ...u16(0),
        ...u16(0x0021),
        ...u32(checksum),
        ...u32(data.length),
        ...u32(data.length),
        ...u16(name.length),
        ...u16(extra.length), // YEREL: 4
        ...name,
        ...extra,
        ...data,
      ]
      const central = [
        ...u32(0x02014b50),
        ...u16(20),
        ...u16(20),
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u16(0x0021),
        ...u32(checksum),
        ...u32(data.length),
        ...u32(data.length),
        ...u16(name.length),
        ...u16(0), // MERKEZÎ: 0 — yerelden farklı
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u32(0),
        ...u32(0),
        ...name,
      ]
      const eocd = [
        ...u32(0x06054b50),
        ...u16(0),
        ...u16(0),
        ...u16(1),
        ...u16(1),
        ...u32(central.length),
        ...u32(local.length),
        ...u16(0),
      ]
      return new Uint8Array([...local, ...central, ...eocd])
    }

    it('veri konumu yerel başlıktan okunuyor', () => {
      const okunan = readZip(craft())
      expect(okunan).toHaveLength(1)
      expect(fromUtf8(okunan[0]?.data ?? new Uint8Array())).toBe('DOGRU')
    })

    /**
     * Açılan boyut merkezî dizinde yazandan farklıysa arşiv bozuktur ve
     * sessizce kabul edilmemeli — kısa okunan bir girdi, imzanın kapsadığı
     * veriden farklı bir veri demektir.
     */
    it('açılan boyut beyan edilenden farklıysa reddediliyor', () => {
      const arsiv = createZip([{ name: 'a.txt', data: utf8('12345'), stored: true }])
      const bozuk = new Uint8Array(arsiv)
      // Merkezî dizindeki açılmış boyutu 5'ten 9'a çıkar.
      const at = bozuk.length - 22 - (46 + 5) + 24
      bozuk[at] = 9
      expect(() => readZip(bozuk)).toThrow(/beklenen boyutta değil/)
    })
  })

  describe('bozuk girdi', () => {
    it('çok küçük dosya reddediliyor', () => {
      expect(() => readZip(new Uint8Array(4))).toThrow(/çok küçük/)
    })

    it('merkezî dizin sonu yoksa reddediliyor', () => {
      expect(() => readZip(new Uint8Array(64))).toThrow(/merkezî dizin sonu/)
    })

    it('bozuk merkezî dizin reddediliyor', () => {
      const arsiv = createZip(entries)
      // Merkezî dizin imzasını boz.
      const bozuk = new Uint8Array(arsiv)
      const at = bozuk.indexOf(0x50, 100)
      bozuk[at] = 0x00
      expect(() => readZip(bozuk)).toThrow()
    })
  })
})

describe('ASiC konteyneri', () => {
  const fatura = { name: 'fatura.xml', data: utf8('<Invoice>ÖRNEK</Invoice>') }
  const ek = { name: 'ek.pdf', data: utf8('%PDF-1.7 sahte') }
  const imza = { format: 'cades' as const, data: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]) }

  it('ASiC-S üretiliyor ve okunuyor', () => {
    const konteyner = createAsic({ type: 'asic-s', dataFiles: [fatura], signatures: [imza] })
    const okunan = readAsic(konteyner)

    expect(okunan.type).toBe('asic-s')
    expect(okunan.mimeType).toBe(ASIC_MIME_TYPE['asic-s'])
    expect(okunan.dataFiles).toHaveLength(1)
    expect(okunan.dataFiles[0]?.name).toBe('fatura.xml')
    expect(okunan.signatures).toHaveLength(1)
    expect(okunan.signatures[0]?.name).toBe('META-INF/signature.p7s')
    expect(okunan.signatures[0]?.format).toBe('cades')
    // ASiC-S'te tek dosya ve tek imza var; manifest gerekmiyor.
    expect(okunan.signatures[0]?.manifest).toBeUndefined()
  })

  it('XAdES imzası signatures.xml olarak paketleniyor', () => {
    const konteyner = createAsic({
      type: 'asic-s',
      dataFiles: [fatura],
      signatures: [{ format: 'xades', data: utf8('<ds:Signature/>') }],
    })
    const okunan = readAsic(konteyner)
    expect(okunan.signatures[0]?.name).toBe('META-INF/signatures.xml')
    expect(okunan.signatures[0]?.format).toBe('xades')
  })

  it('ASiC-E çok dosya ve manifest ile üretiliyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura, ek],
      signatures: [imza],
    })
    const okunan = readAsic(konteyner)

    expect(okunan.type).toBe('asic-e')
    expect(okunan.dataFiles).toHaveLength(2)
    expect(okunan.signatures[0]?.name).toBe('META-INF/signature001.p7s')

    const manifest = okunan.signatures[0]?.manifest
    expect(manifest).toBeDefined()
    expect(manifest?.name).toBe('META-INF/ASiCManifest001.xml')
    expect(manifest?.signatureReference).toBe('META-INF/signature001.p7s')
    expect(manifest?.references).toHaveLength(2)
    expect(manifest?.references.every((ref) => ref.present && ref.digestMatches)).toBe(true)
  })

  it('imzanın kapsadığı dosyalar sınırlanabiliyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura, ek],
      signatures: [{ ...imza, covers: ['fatura.xml'] }],
    })
    const manifest = readAsic(konteyner).signatures[0]?.manifest
    expect(manifest?.references).toHaveLength(1)
    expect(manifest?.references[0]?.uri).toBe('fatura.xml')
  })

  it('birden çok imza ayrı manifestlerle numaralanıyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura, ek],
      signatures: [imza, { ...imza, covers: ['ek.pdf'] }],
    })
    const okunan = readAsic(konteyner)
    expect(okunan.signatures.map((item) => item.name)).toStrictEqual([
      'META-INF/signature001.p7s',
      'META-INF/signature002.p7s',
    ])
    expect(okunan.signatures[1]?.manifest?.references[0]?.uri).toBe('ek.pdf')
  })

  /**
   * Manifesti okuyup özetleri doğrulamamak, imzanın kapsadığını iddia ettiği
   * dosyanın gerçekten o dosya olduğunu VARSAYMAK olurdu. Bu test, dosya
   * değişince özet uyuşmazlığının raporlandığını sabitliyor.
   */
  it('veri dosyası değişirse manifest özeti tutmuyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura],
      signatures: [imza],
    })
    // Konteyneri açıp veri dosyasını değiştirip yeniden paketle.
    const girdiler = readZip(konteyner).map((entry) =>
      entry.name === 'fatura.xml'
        ? { ...entry, data: utf8('<Invoice>DEGISTIRILDI</Invoice>') }
        : entry,
    )
    const bozuk = createZip(girdiler)

    const manifest = readAsic(bozuk).signatures[0]?.manifest
    expect(manifest?.references[0]?.present).toBe(true)
    expect(manifest?.references[0]?.digestMatches).toBe(false)
  })

  it('manifestteki dosya konteynerde yoksa raporlanıyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura],
      signatures: [imza],
    })
    const girdiler = readZip(konteyner).filter((entry) => entry.name !== 'fatura.xml')
    const manifest = readAsic(createZip(girdiler)).signatures[0]?.manifest
    expect(manifest?.references[0]?.present).toBe(false)
  })

  it.skipIf(!hasUnzip)('unzip ASiC konteynerini sağlam buluyor', () => {
    const konteyner = createAsic({
      type: 'asic-e',
      dataFiles: [fatura, ek],
      signatures: [imza],
    })
    expect(unzip(konteyner, ['-t'])).toContain('No errors detected')
    const liste = unzip(konteyner, ['-l'])
    expect(liste).toContain('mimetype')
    expect(liste).toContain('META-INF/ASiCManifest001.xml')
  })

  describe('kısıtlar', () => {
    it('veri dosyası olmadan reddediliyor', () => {
      expect(() => createAsic({ type: 'asic-s', dataFiles: [], signatures: [imza] })).toThrow(
        /en az bir veri dosyası/,
      )
    })

    it('imza olmadan reddediliyor', () => {
      expect(() => createAsic({ type: 'asic-s', dataFiles: [fatura], signatures: [] })).toThrow(
        /en az bir imza/,
      )
    })

    /** ASiC-S kısıtları standardın kendi kısıtları; esnetmek okuyucuları kırar. */
    it('ASiC-S birden çok dosya ya da imza kabul etmiyor', () => {
      expect(() =>
        createAsic({ type: 'asic-s', dataFiles: [fatura, ek], signatures: [imza] }),
      ).toThrow(/tek veri dosyası/)
      expect(() =>
        createAsic({ type: 'asic-s', dataFiles: [fatura], signatures: [imza, imza] }),
      ).toThrow(/tek imza/)
    })

    it('ayrılmış dosya adları reddediliyor', () => {
      for (const name of ['mimetype', 'META-INF/signature.p7s']) {
        expect(() =>
          createAsic({
            type: 'asic-s',
            dataFiles: [{ name, data: utf8('x') }],
            signatures: [imza],
          }),
        ).toThrow(SigningError)
      }
    })

    it('kapsanan dosya konteynerde yoksa reddediliyor', () => {
      expect(() =>
        createAsic({
          type: 'asic-e',
          dataFiles: [fatura],
          signatures: [{ ...imza, covers: ['olmayan.pdf'] }],
        }),
      ).toThrow(/konteynerde yok/)
    })
  })

  describe('okuma hataları', () => {
    it('ASiC olmayan ZIP reddediliyor', () => {
      const arsiv = createZip([{ name: 'a.txt', data: utf8('x') }])
      expect(() => readAsic(arsiv)).toThrow(/ilk girdi/)
    })

    it('tanınmayan mimetype reddediliyor', () => {
      const arsiv = createZip([{ name: 'mimetype', data: utf8('application/zip'), stored: true }])
      expect(() => readAsic(arsiv)).toThrow(/tanınmayan mimetype/)
    })

    it('ZIP olmayan girdi reddediliyor', () => {
      expect(() => readAsic(utf8('bu bir ZIP değil'))).toThrow(VerificationError)
    })
  })
})

describe.skipIf(!canGenerateKeyMaterial())('uçtan uca: imzala ve paketle', () => {
  /**
   * ASiC'in gerçek kullanımı: bir belgeyi imzalayıp imzasıyla birlikte tek
   * dosyada taşımak. Konteyner imzayı görmüyor — okuyan taraf onu çıkarıp
   * ayrıca doğruluyor.
   */
  it('CAdES imzası paketleniyor, açılıyor ve doğrulanıyor', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const belge = utf8('<Invoice>ÖRNEK SATICI A.Ş. — 1.180,00 TL</Invoice>')

    const imza = cadesSign({
      data: belge,
      signer: { certificate: bundle.certificate, chain: bundle.chain },
      privateKey: bundle.privateKey,
      attached: false,
      commitmentType: 'proof-of-origin',
    })

    const konteyner = createAsic({
      type: 'asic-s',
      dataFiles: [{ name: 'fatura.xml', data: belge }],
      signatures: [{ format: 'cades', data: imza }],
    })

    const okunan = readAsic(konteyner)
    const veri = okunan.dataFiles[0]?.data
    const cikarilan = okunan.signatures[0]?.data
    expect(veri).toBeDefined()
    expect(cikarilan).toBeDefined()
    if (veri === undefined || cikarilan === undefined) return

    const sonuc = cadesVerify(cikarilan, { content: veri })
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.level).toBe('BES')
    expect(sonuc.signer.subjectSerialNumber).toBe('1234567890')
  })

  it('paketteki veri değişirse imza düşüyor', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const belge = utf8('<Invoice>1180.00</Invoice>')
    const imza = cadesSign({
      data: belge,
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
      attached: false,
    })
    const konteyner = createAsic({
      type: 'asic-s',
      dataFiles: [{ name: 'fatura.xml', data: belge }],
      signatures: [{ format: 'cades', data: imza }],
    })

    const bozuk = createZip(
      readZip(konteyner).map((entry) =>
        entry.name === 'fatura.xml'
          ? { ...entry, data: utf8('<Invoice>9999.00</Invoice>') }
          : entry,
      ),
    )
    const okunan = readAsic(bozuk)
    const sonuc = cadesVerify(okunan.signatures[0]?.data ?? new Uint8Array(), {
      content: okunan.dataFiles[0]?.data ?? new Uint8Array(),
    })
    expect(sonuc.valid).toBe(false)
  })
})

describe('unzip mevcudiyeti', () => {
  it('unzip bulunmalı — yoksa çapraz doğrulama sessizce atlanır', () => {
    expect(hasUnzip).toBe(true)
  })
})
