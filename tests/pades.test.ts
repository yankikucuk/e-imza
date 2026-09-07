import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { cadesSignWithKey } from '../src/cades/sign.js'
import { fromUtf8, utf8 } from '../src/core/bytes.js'
import { SigningError, VerificationError } from '../src/core/errors.js'
import { padesComplete, padesPrepare, padesSign } from '../src/pades/sign.js'
import { padesVerify } from '../src/pades/verify.js'
import { catalog, firstPage, readPdf } from '../src/pdf/document.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'
import { minimalPdf, pdfWithXrefStream } from './pdf-fixture.js'

/**
 * PAdES — PDF imzası.
 *
 * En değerli test grubu **poppler `pdfsig` çapraz doğrulaması**: bağımsız
 * bir PDF imza doğrulayıcısı bizim imzamızı kabul ediyorsa, artımlı
 * güncelleme, `/ByteRange` hesabı, imza sözlüğü ve gömülü CAdES'in hepsi
 * doğru demektir.
 */

const directory = mkdtempSync(join(tmpdir(), 'e-imza-pades-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

const hasPdfsig = ((): boolean => {
  try {
    execFileSync('pdfsig', ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

let counter = 0
/** `pdfsig` çıktısını verir. */
const pdfsig = (pdf: Uint8Array): string => {
  counter += 1
  const file = join(directory, `imzali-${String(counter)}.pdf`)
  writeFileSync(file, pdf)
  try {
    return execFileSync('pdfsig', [file], { encoding: 'utf8' })
  } catch (error) {
    const out = (error as { stdout?: Buffer }).stdout
    return out === undefined ? '' : out.toString('utf8')
  }
}

describe.skipIf(!canGenerateKeyMaterial())('PAdES', () => {
  const anahtar = (): ReturnType<typeof loadPkcs12> => {
    const { modernRsa } = keyMaterial()
    return loadPkcs12(modernRsa.p12, modernRsa.password)
  }

  const imzala = (options: Partial<Parameters<typeof padesSign>[0]> = {}): Uint8Array => {
    const bundle = anahtar()
    return padesSign({
      pdf: minimalPdf(),
      signer: { certificate: bundle.certificate, chain: bundle.chain },
      privateKey: bundle.privateKey,
      ...options,
    })
  }

  it('PDF imzalanıyor ve kendi doğrulayıcımız kabul ediyor', () => {
    const sonuc = padesVerify(imzala())
    expect(sonuc.valid).toBe(true)
    expect(sonuc.signatures).toHaveLength(1)
    const imza = sonuc.signatures[0]
    expect(imza?.valid).toBe(true)
    expect(imza?.coversWholeDocument).toBe(true)
    expect(imza?.signer?.subjectName).toContain('Ornek Mali Muhur')
    expect(imza?.signingTime).toBeInstanceOf(Date)
  })

  /**
   * Asıl kanıt. poppler'ın `pdfsig`i bizden bağımsız bir uygulama; imzayı
   * kabul ediyorsa artımlı güncelleme, `/ByteRange` hesabı, imza sözlüğü ve
   * gömülü CAdES'in hepsi doğru demektir.
   *
   * "Certificate issuer is unknown" beklenen: test kökümüz sistem güven
   * deposunda yok. O, zincir doğrulaması — imza doğrulaması değil.
   */
  it.skipIf(!hasPdfsig)('poppler pdfsig imzamızı geçerli buluyor', () => {
    const cikti = pdfsig(imzala())
    expect(cikti).toContain('Signature is Valid')
    expect(cikti).toContain('Total document signed')
    expect(cikti).toContain('ETSI.CAdES.detached')
  })

  it.skipIf(!hasPdfsig)('pdfsig imzalayan bilgilerini okuyor', () => {
    const cikti = pdfsig(imzala({ reason: 'Onay', location: 'Istanbul' }))
    expect(cikti).toContain('Ornek Mali Muhur')
    expect(cikti).toContain('SHA-256')
  })

  /**
   * PAdES'in temel kuralı: özgün baytlara dokunulmaz. Dokunulsaydı daha
   * önce atılmış imzalar bozulurdu — ve üst üste imza atmak imkânsız olurdu.
   */
  it('özgün baytlar bayt bayt korunuyor', () => {
    const pdf = minimalPdf()
    const imzali = imzala({ pdf })
    expect(imzali.length).toBeGreaterThan(pdf.length)
    expect(fromUtf8(imzali.subarray(0, pdf.length))).toBe(fromUtf8(pdf))
  })

  it('belge değiştirilirse doğrulama düşüyor', () => {
    const imzali = imzala()
    // Sayfa boyutundaki tek bir rakamı değiştir.
    const metin = fromUtf8(imzali)
    const bozuk = utf8(metin.replace('612 792', '612 793'))
    expect(bozuk.length).toBe(imzali.length)

    const sonuc = padesVerify(bozuk)
    expect(sonuc.valid).toBe(false)
    expect(sonuc.signatures[0]?.reason).toContain('messageDigest')
  })

  it.skipIf(!hasPdfsig)('bozuk belgeyi pdfsig de reddediyor', () => {
    const imzali = imzala()
    const bozuk = utf8(fromUtf8(imzali).replace('612 792', '612 793'))
    expect(pdfsig(bozuk)).not.toContain('Signature is Valid')
  })

  describe('yapı', () => {
    it('imza sözlüğü ve form alanı yazılıyor', () => {
      const imzali = imzala()
      const metin = fromUtf8(imzali)
      expect(metin).toContain('/Type /Sig')
      expect(metin).toContain('/SubFilter /ETSI.CAdES.detached')
      expect(metin).toContain('/Subtype /Widget')
      expect(metin).toContain('/SigFlags 3')
    })

    it('katalog ve sayfa güncelleniyor, çapraz başvuru zincirleniyor', () => {
      const pdf = minimalPdf()
      const imzali = imzala({ pdf })
      const okunan = readPdf(imzali)

      // `/Prev` zinciri özgün tabloya bağlanıyor.
      expect(okunan.trailer.get('Prev')).toBeDefined()
      // Katalog ve sayfa hâlâ çözülebiliyor.
      expect(catalog(okunan).reference).toBe(1)
      expect(firstPage(okunan).reference).toBe(3)
      expect(okunan.size).toBeGreaterThan(readPdf(pdf).size)
    })

    /**
     * İmzadan artan bölge sıfırlarla dolu kalmalı: `/Contents` sabit
     * genişliktedir ve oraya çöp yazmak dosyayı bozar. Doğrulayıcı ilk DER
     * değerini alıp kalanı atıyor, ama o "kalan"ın da geçerli onaltılık
     * olması gerekiyor.
     */
    it('imzadan artan yer sıfırla dolu kalıyor', () => {
      const metin = fromUtf8(imzala())
      const eslesme = /\/Contents <([0-9a-f]+)>/.exec(metin)
      expect(eslesme).not.toBeNull()
      const alan = eslesme?.[1] ?? ''
      expect(alan).toHaveLength(16384)
      expect(alan.endsWith('0'.repeat(64))).toBe(true)
      expect(/^[0-9a-f]+$/.test(alan)).toBe(true)
    })

    it('çapraz başvuru AKIŞI kullanan PDF de imzalanıyor', () => {
      const imzali = imzala({ pdf: pdfWithXrefStream() })
      const sonuc = padesVerify(imzali)
      expect(sonuc.valid).toBe(true)
      expect(sonuc.signatures[0]?.coversWholeDocument).toBe(true)
    })

    it('çok sayfalı belgede ilk sayfaya bağlanıyor', () => {
      const sonuc = padesVerify(imzala({ pdf: minimalPdf({ pages: 3 }) }))
      expect(sonuc.valid).toBe(true)
    })
  })

  describe('imza sözlüğü alanları', () => {
    it('gerekçe ve yer geri okunuyor', () => {
      const sonuc = padesVerify(imzala({ reason: 'Fatura onayi', location: 'Ankara' }))
      expect(sonuc.signatures[0]?.reasonText).toBe('Fatura onayi')
      expect(sonuc.signatures[0]?.location).toBe('Ankara')
    })

    /**
     * ASCII dışı karakterler UTF-16BE ve bayt sırası işaretiyle yazılmak
     * zorunda; Latin-1 yazmak görüntüleyicide bozuk çıkar.
     */
    it('Türkçe karakterler kayıpsız gidip geliyor', () => {
      const sonuc = padesVerify(imzala({ reason: 'Ödeme onayı — Ş Ğ İ ı', location: 'İstanbul' }))
      expect(sonuc.signatures[0]?.reasonText).toBe('Ödeme onayı — Ş Ğ İ ı')
      expect(sonuc.signatures[0]?.location).toBe('İstanbul')
    })

    it('signingTime null verilince tarih yazılmıyor', () => {
      const imzali = imzala({ signingTime: null })
      expect(fromUtf8(imzali)).not.toContain('/M (D:')
      expect(padesVerify(imzali).valid).toBe(true)
    })
  })

  describe('birden çok imza', () => {
    /**
     * Artımlı güncelleme sayesinde ikinci imza birincisini bozmuyor. Ama
     * birinci imza artık belgenin TAMAMINI kapsamıyor — ikinci imza onun
     * kapsamı dışında ve bu raporlanmalı. Sessizce "geçerli" demek,
     * kullanıcıya imzanın kapsamadığı içeriği kapsıyormuş gibi göstermek
     * olurdu.
     */
    it('ikinci imza birinciyi bozmuyor ama kapsam daralıyor', () => {
      const bundle = anahtar()
      const bir = imzala()
      const iki = padesSign({
        pdf: bir,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
      })

      const sonuc = padesVerify(iki)
      expect(sonuc.signatures).toHaveLength(2)
      expect(sonuc.valid).toBe(true)

      const kapsayanlar = sonuc.signatures.filter((imza) => imza.coversWholeDocument)
      expect(kapsayanlar).toHaveLength(1)

      const kismi = sonuc.signatures.find((imza) => !imza.coversWholeDocument)
      expect(kismi?.valid).toBe(true)
      expect(kismi?.warnings.map((uyari) => uyari.code)).toContain('partial-coverage')
    })

    it.skipIf(!hasPdfsig)('pdfsig de iki imzayı görüyor', () => {
      const bundle = anahtar()
      const iki = padesSign({
        pdf: imzala(),
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
      })
      const cikti = pdfsig(iki)
      expect(cikti).toContain('Signature #1')
      expect(cikti).toContain('Signature #2')
    })
  })

  describe('ayrık imzalama', () => {
    it('prepare/complete ile imza dışarıda üretiliyor', () => {
      const bundle = anahtar()
      const bekleyen = padesPrepare({
        pdf: minimalPdf(),
        signer: { certificate: bundle.certificate },
      })
      expect(bekleyen.dataToSign.length).toBeGreaterThan(0)
      expect(bekleyen.digestInfo).toBeDefined()
      expect(bekleyen.keyKind).toBe('rsa')

      const imza = cadesSignWithKey(
        {
          dataToSign: bekleyen.dataToSign,
          digest: bekleyen.digest,
          digestAlgorithm: bekleyen.digestAlgorithm,
          keyKind: bekleyen.keyKind,
          build: () => new Uint8Array(0),
        },
        bundle.privateKey,
      )
      const imzali = padesComplete(bekleyen, imza)
      expect(padesVerify(imzali).valid).toBe(true)
    })
  })

  describe('EC anahtar', () => {
    it('EC ile imzalanıyor', () => {
      const { modernEc } = keyMaterial()
      const bundle = loadPkcs12(modernEc.p12, modernEc.password)
      const imzali = padesSign({
        pdf: minimalPdf(),
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
      })
      expect(padesVerify(imzali).valid).toBe(true)
    })
  })

  describe('hata durumları', () => {
    /**
     * PDF'te imzanın boyutu imza atılmadan ÖNCE ayrılmak zorunda: yer
     * ayrılmadan `/ByteRange` hesaplanamaz. Sığmayan bir imzayı sessizce
     * kırpmak bozuk bir dosya üretirdi.
     */
    it('ayrılan yer yetmezse açık hata veriyor', () => {
      const bundle = anahtar()
      expect(() =>
        padesSign({
          pdf: minimalPdf(),
          signer: { certificate: bundle.certificate, chain: bundle.chain },
          privateKey: bundle.privateKey,
          signatureSpace: 1024,
        }),
      ).toThrow(/ayrılan yere sığmıyor/)
    })

    it('geçersiz alan boyutu reddediliyor', () => {
      const bundle = anahtar()
      for (const signatureSpace of [512, 4097]) {
        expect(() =>
          padesSign({
            pdf: minimalPdf(),
            signer: { certificate: bundle.certificate },
            privateKey: bundle.privateKey,
            signatureSpace,
          }),
        ).toThrow(SigningError)
      }
    })

    it('PDF olmayan girdi reddediliyor', () => {
      const bundle = anahtar()
      expect(() =>
        padesSign({
          pdf: utf8('bu bir PDF değil'),
          signer: { certificate: bundle.certificate },
          privateKey: bundle.privateKey,
        }),
      ).toThrow(/%PDF-/)
    })

    it('imzasız PDF doğrulanamıyor', () => {
      expect(() => padesVerify(minimalPdf())).toThrow(VerificationError)
    })

    /**
     * Şifreli PDF'e imza eklemek belgeyi çözmeyi gerektirir. Sessizce
     * denemek bozuk bir dosya üretirdi.
     */
    it('şifreli PDF açıkça reddediliyor', () => {
      const pdf = minimalPdf()
      const metin = fromUtf8(pdf).replace(
        '/Size 4 /Root 1 0 R',
        '/Size 4 /Root 1 0 R /Encrypt 9 0 R',
      )
      const bundle = anahtar()
      expect(() =>
        padesSign({
          pdf: utf8(metin),
          signer: { certificate: bundle.certificate },
          privateKey: bundle.privateKey,
        }),
      ).toThrow(/şifreli/)
    })
  })
})

describe('pdfsig mevcudiyeti', () => {
  it('pdfsig bulunmalı — yoksa çapraz doğrulama sessizce atlanır', () => {
    expect(hasPdfsig).toBe(true)
  })
})
