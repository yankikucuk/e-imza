import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { cadesSignWithKey } from '../src/cades/sign.js'
import { cadesTimestampRequest, cadesUpgrade } from '../src/cades/upgrade.js'
import { fromUtf8, toHex, utf8 } from '../src/core/bytes.js'
import { SigningError } from '../src/core/errors.js'
import { readDocumentSecurityStore, vriKey } from '../src/pades/dss.js'
import { padesPrepare } from '../src/pades/sign.js'
import { padesDocumentTimestamp, padesUpgrade } from '../src/pades/upgrade.js'
import { padesVerify } from '../src/pades/verify.js'
import { readPdf } from '../src/pdf/document.js'
import { indexOfSequence } from '../src/pdf/object.js'
import { buildOcspRequest } from '../src/pki/ocsp.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { parseTimestampResponse } from '../src/pki/tsp.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'
import { minimalPdf } from './pdf-fixture.js'

/**
 * PAdES-LT ve PAdES-LTA — uzun dönem doğrulanabilirlik.
 *
 * Buradaki asıl soru şu: ürettiğimiz DSS ve `/DocTimeStamp`, **bizden
 * bağımsız** bir okuyucu için de anlamlı mı? İki bağımsız tanık var:
 *
 * - **poppler `pdfsig`** — belgeyi hâlâ okuyup imzayı doğruluyor mu,
 * - **OpenSSL** — `/VRI` anahtarı gerçekten `/Contents`in SHA-1'i mi.
 *
 * `/VRI` özellikle önemli: değeri yalnızca BAŞKA bir doğrulayıcıyla
 * eşleştiğinde işe yarar. Kendi `vriKey`imizle karşılaştırmak hiçbir şey
 * kanıtlamaz — iki taraf da biziz.
 */

const directory = mkdtempSync(join(tmpdir(), 'e-imza-ltv-'))
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
  const file = join(directory, `ltv-${String(counter)}.pdf`)
  writeFileSync(file, pdf)
  try {
    return execFileSync('pdfsig', [file], { encoding: 'utf8' })
  } catch (error) {
    const out = (error as { stdout?: Buffer }).stdout
    return out === undefined ? '' : out.toString('utf8')
  }
}

describe.skipIf(!canGenerateKeyMaterial())('PAdES-LT / PAdES-LTA', () => {
  /** İmzalı (B-B) PDF ve kullanılan malzeme. */
  const imzala = (): {
    pdf: Uint8Array
    cms: Uint8Array
    finish: (der: Uint8Array) => Uint8Array
  } => {
    const { withChain } = keyMaterial()
    const bundle = loadPkcs12(withChain.p12, withChain.password)
    const pending = padesPrepare({
      pdf: minimalPdf(),
      signer: { certificate: bundle.certificate, chain: bundle.chain },
    })
    const cms = pending.completeCades(
      cadesSignWithKey(
        {
          dataToSign: pending.dataToSign,
          digest: pending.digest,
          digestAlgorithm: pending.digestAlgorithm,
          keyKind: pending.keyKind,
          build: () => new Uint8Array(0),
          ...(pending.digestInfo === undefined ? {} : { digestInfo: pending.digestInfo }),
        },
        bundle.privateKey,
      ),
    )
    return { pdf: pending.finish(cms), cms, finish: pending.finish }
  }

  /** Zaman damgalı (B-T) PDF. */
  const damgala = (): Uint8Array => {
    const { tsa } = keyMaterial()
    const { cms, finish } = imzala()
    const token = parseTimestampResponse(tsa.issue(cadesTimestampRequest({ cms })))
    return finish(cadesUpgrade({ cms, to: 'T', token }))
  }

  /**
   * Doğrulama malzemesi: ara CA, kök ve imzalayan için OCSP yanıtı.
   *
   * **Bir kez** üretilip saklanıyor: `openssl ocsp` her çağrıda `producedAt`
   * ve imzası farklı bir yanıt döndürür, iki ayrı çağrıyı bayt bayt
   * karşılaştıran bir test saniye sınırına göre rastgele kırılırdı.
   */
  let malzemeOnbellek: { certificates: Uint8Array[]; ocspResponses: Uint8Array[] } | undefined
  const malzeme = (): { certificates: Uint8Array[]; ocspResponses: Uint8Array[] } => {
    if (malzemeOnbellek !== undefined) return malzemeOnbellek
    const material = keyMaterial()
    const bundle = loadPkcs12(material.withChain.p12, material.withChain.password)
    const request = buildOcspRequest({
      certificate: bundle.certificate,
      issuer: material.intermediateCertificate,
    })
    malzemeOnbellek = {
      certificates: [material.intermediateCertificate, material.rootCertificate],
      ocspResponses: [material.ocsp.respond(request)],
    }
    return malzemeOnbellek
  }

  /** B-LT seviyesine getirilmiş PDF. */
  const uzunDonem = (): Uint8Array => padesUpgrade({ pdf: damgala(), to: 'LT', ...malzeme() })

  /** B-LTA seviyesine getirilmiş PDF. */
  const arsiv = (pdf = uzunDonem()): Uint8Array => {
    const { tsa } = keyMaterial()
    const pending = padesDocumentTimestamp({ pdf })
    return pending.finish(parseTimestampResponse(tsa.issue(pending.request)))
  }

  /**
   * Özgün gövdede — her imzanın ve her damganın kapsadığı bölgede — tek bir
   * baytı değiştirir. `/MediaBox` sayfanın kendi sözlüğünde ve dosyanın en
   * başına yakın; hiçbir imza alanının içinde değil.
   */
  const bozulmus = (pdf: Uint8Array): Uint8Array =>
    kismiDegistir(pdf, [['/MediaBox [0 0 612 792]', '/MediaBox [0 0 611 792]']])

  /**
   * Dosyada AYNI UZUNLUKTA metin değişimi yapar.
   *
   * Uzunluk korunduğu için çapraz başvurudaki konumlar geçerli kalıyor;
   * PDF'i yeniden kurmadan yalnızca ilgilendiğimiz alanı değiştirebiliyoruz.
   */
  const kismiDegistir = (
    pdf: Uint8Array,
    degisimler: readonly (readonly [string, string])[],
  ): Uint8Array => {
    const out = new Uint8Array(pdf)
    for (const [eski, yeni] of degisimler) {
      if (eski.length !== yeni.length) throw new Error('uzunluklar eşit olmalı')
      const at = indexOfSequence(out, utf8(eski))
      if (at === -1) throw new Error(`bulunamadı: ${eski}`)
      out.set(utf8(yeni), at)
    }
    return out
  }

  describe('DSS — doğrulama malzemesi', () => {
    it('LT yükseltmesi malzemeyi belgeye BAYT BAYT aynı gömüyor', () => {
      const beklenen = malzeme()
      const dss = readDocumentSecurityStore(uzunDonem())
      expect(dss).toBeDefined()
      expect(dss?.certificates.map((c) => toHex(c))).toEqual(
        beklenen.certificates.map((c) => toHex(c)),
      )
      expect(dss?.ocspResponses.map((o) => toHex(o))).toEqual(
        beklenen.ocspResponses.map((o) => toHex(o)),
      )
    })

    it('LT yükseltmesi imzayı bozmuyor ve seviye B-LT oluyor', () => {
      const sonuc = padesVerify(uzunDonem())
      expect(sonuc.valid).toBe(true)
      expect(sonuc.signatures[0]?.valid).toBe(true)
      expect(sonuc.signatures[0]?.level).toBe('B-LT')
      expect(sonuc.signatures[0]?.hasVri).toBe(true)
    })

    /**
     * DSS artımlı bir güncellemeyle geliyor; imzanın `/ByteRange`ı onu
     * kapsamaz. Bu beklenen ve doğru olan davranış — ama sessiz kalmamalı.
     */
    it('DSS eklendikten sonra imza artık belgenin tamamını kapsamıyor', () => {
      const imza = padesVerify(uzunDonem()).signatures[0]
      expect(imza?.coversWholeDocument).toBe(false)
      expect(imza?.warnings.map((w) => w.code)).toContain('partial-coverage')
    })

    it('ikinci LT yükseltmesi ilkinin malzemesini KORUYOR', () => {
      const material = keyMaterial()
      const ilk = uzunDonem()
      const ikinci = padesUpgrade({
        pdf: ilk,
        to: 'LT',
        certificates: [material.tsa.certificate],
      })
      const dss = readDocumentSecurityStore(ikinci)
      // İlk turdaki iki sertifika + TSA sertifikası.
      expect(dss?.certificates).toHaveLength(3)
      expect(dss?.ocspResponses).toHaveLength(1)
      expect(padesVerify(ikinci).signatures[0]?.valid).toBe(true)
    })

    it('aynı sertifika iki kez verilirse belgeye bir kez giriyor', () => {
      const material = keyMaterial()
      const pdf = padesUpgrade({
        pdf: damgala(),
        to: 'LT',
        certificates: [material.rootCertificate, material.rootCertificate],
      })
      expect(readDocumentSecurityStore(pdf)?.certificates).toHaveLength(1)
    })

    it('imzasız belgeye DSS eklenmiyor', () => {
      expect(() =>
        padesUpgrade({ pdf: minimalPdf(), to: 'LT', certificates: [new Uint8Array([1])] }),
      ).toThrow(SigningError)
    })

    it('boş malzemeyle DSS eklenmiyor', () => {
      expect(() => padesUpgrade({ pdf: damgala(), to: 'LT' })).toThrow(SigningError)
    })

    it('katalogda ADBE uzantı bildirimi var', () => {
      const metin = fromUtf8(uzunDonem())
      expect(metin).toContain('/ExtensionLevel 5')
      expect(metin).toContain('/BaseVersion /1.7')
    })
  })

  describe('/VRI anahtarı', () => {
    /**
     * Bağımsız tanık. `/Contents` onaltılığı dosyadan doğrudan okunuyor,
     * çözülüyor ve SHA-1'i **OpenSSL'e** hesaplatılıyor. Kendi `vriKey`imiz
     * bu değere eşit değilse ürettiğimiz `/VRI` başka hiçbir doğrulayıcıda
     * eşleşmez.
     */
    it('OpenSSL, /VRI anahtarını /Contents baytlarının SHA-1i olarak doğruluyor', () => {
      const pdf = uzunDonem()
      const metin = fromUtf8(pdf)
      const eslesme = /\/Contents <([0-9a-f]+)>/.exec(metin)
      expect(eslesme).not.toBeNull()
      const hex = eslesme?.[1] ?? ''

      const ham = join(directory, 'contents.bin')
      writeFileSync(ham, Buffer.from(hex, 'hex'))
      const cikti = execFileSync('openssl', ['dgst', '-sha1', '-r', ham], { encoding: 'utf8' })
      const beklenen = (cikti.split(' ')[0] ?? '').toUpperCase()

      expect(beklenen).toHaveLength(40)
      const dss = readDocumentSecurityStore(pdf)
      expect(dss?.vriKeys).toEqual([beklenen])
    })

    it('vriKey dolgulu baytları özetliyor — DER kırpılmış hâli DEĞİL', () => {
      const dolgusuz = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])
      const dolgulu = new Uint8Array(16)
      dolgulu.set(dolgusuz)
      expect(vriKey(dolgulu)).not.toBe(vriKey(dolgusuz))
    })
  })

  describe('/DocTimeStamp — belge zaman damgası', () => {
    it('damga atılıyor, doğrulanıyor ve seviye B-LTA oluyor', () => {
      const sonuc = padesVerify(arsiv())
      expect(sonuc.valid).toBe(true)
      expect(sonuc.documentTimestamps).toHaveLength(1)
      expect(sonuc.documentTimestamps[0]?.valid).toBe(true)
      expect(sonuc.documentTimestamps[0]?.genTime).toBeInstanceOf(Date)
      expect(sonuc.documentTimestamps[0]?.coversWholeDocument).toBe(true)
      expect(sonuc.signatures[0]?.level).toBe('B-LTA')
    })

    it('damga sözlüğü /DocTimeStamp ve /ETSI.RFC3161 taşıyor', () => {
      const metin = fromUtf8(arsiv())
      expect(metin).toContain('/Type /DocTimeStamp')
      expect(metin).toContain('/SubFilter /ETSI.RFC3161')
    })

    /**
     * `/M` YAZILMAMALI: damganın zamanı jetonun içindedir. Sözlüğe ikinci
     * bir zaman koymak, çelişebilecek iki kaynak yaratır.
     */
    it('damga sözlüğünde /M yok', () => {
      const pdf = arsiv()
      const document = readPdf(pdf)
      const damga = padesVerify(pdf).documentTimestamps[0]
      expect(damga).toBeDefined()
      const sozluk = document.xref.has(damga?.objectNumber ?? -1)
      expect(sozluk).toBe(true)
      // Damga sözlüğünün metni: /Type /DocTimeStamp ile başlayan blok.
      const metin = fromUtf8(pdf)
      const at = metin.indexOf('/Type /DocTimeStamp')
      const blok = metin.slice(at, metin.indexOf('>>', at))
      expect(blok).not.toContain('/M (')
    })

    it('damga, imzayı ve DSSi kapsıyor — damgadan sonra imza hâlâ geçerli', () => {
      const pdf = arsiv()
      const sonuc = padesVerify(pdf)
      expect(sonuc.signatures[0]?.valid).toBe(true)
      expect(readDocumentSecurityStore(pdf)?.certificates).toHaveLength(2)
    })

    it('damgadan sonra tek bayt değişirse damga da imza da tutmuyor', () => {
      const bozuk = bozulmus(arsiv())
      const sonuc = padesVerify(bozuk)
      expect(sonuc.documentTimestamps[0]?.valid).toBe(false)
      expect(sonuc.signatures[0]?.valid).toBe(false)
      expect(sonuc.valid).toBe(false)
    })

    it('başka bir belgenin jetonu reddediliyor', () => {
      const { tsa } = keyMaterial()
      const baskasi = padesDocumentTimestamp({ pdf: uzunDonem() })
      const jeton = parseTimestampResponse(tsa.issue(baskasi.request))

      const bizimki = padesDocumentTimestamp({ pdf: arsiv() })
      expect(() => bizimki.finish(jeton)).toThrow(SigningError)
    })

    it('verifyToken kapatılırsa yanlış jeton gömülebiliyor ama doğrulama yakalıyor', () => {
      const { tsa } = keyMaterial()
      const baskasi = padesDocumentTimestamp({ pdf: uzunDonem() })
      const jeton = parseTimestampResponse(tsa.issue(baskasi.request))

      const bizimki = padesDocumentTimestamp({ pdf: arsiv() })
      const bozuk = bizimki.finish(jeton, { verifyToken: false })
      const sonuc = padesVerify(bozuk)
      expect(sonuc.valid).toBe(false)
      expect(sonuc.documentTimestamps.some((d) => !d.valid)).toBe(true)
    })

    /**
     * LTA'nın varlık nedeni damganın YENİLENEBİLİR olması: gömülü OCSP
     * yanıtını imzalayan sertifikanın da bir gün süresi dolar ve zincir
     * yeni bir damgayla uzatılır. Eski damga, kendi kapsadığı baytlar
     * değişmediği için tutmaya devam etmeli.
     */
    it('ikinci arşiv damgası atılabiliyor, eskisi tutmaya devam ediyor', () => {
      const ilk = arsiv()
      const ikinci = arsiv(ilk)
      const sonuc = padesVerify(ikinci)
      expect(sonuc.valid).toBe(true)
      expect(sonuc.documentTimestamps).toHaveLength(2)
      expect(sonuc.documentTimestamps.every((d) => d.valid)).toBe(true)
      // Yalnızca sonuncusu belgenin tamamını kapsar.
      expect(sonuc.documentTimestamps.map((d) => d.coversWholeDocument)).toEqual([false, true])
      expect(sonuc.signatures[0]?.level).toBe('B-LTA')
    })

    /**
     * Bazı üreticiler belge damgasına `/Type /Sig` yazıyor; ayırt eden tek
     * şey `/SubFilter /ETSI.RFC3161` oluyor. O yedek yol olmazsa damga
     * "imzalayanı olmayan bozuk imza" gibi görünür ve belge sahte biçimde
     * geçersiz raporlanır.
     *
     * `/DocTimeStamp` ile `/Sig` + dolgu AYNI UZUNLUKTA yazılıyor ki
     * konumlar kaymasın.
     */
    it('/Type /Sig yazılmış damga da damga olarak SINIFLANDIRILIYOR', () => {
      const bozuk = kismiDegistir(arsiv(), [['/Type /DocTimeStamp', '/Type /Sig         ']])
      const sonuc = padesVerify(bozuk)
      // Sınıflandırma doğru: damga damga sayılıyor, imza sayısı artmıyor.
      expect(sonuc.documentTimestamps).toHaveLength(1)
      expect(sonuc.signatures).toHaveLength(1)
      // Sınama yalnızca SINIFLANDIRMA hakkında: `/Type` damganın kendi
      // sözlüğünde ve damganın kapsadığı bölgenin İÇİNDE, dolayısıyla onu
      // değiştirmek damgayı zorunlu olarak geçersiz kılıyor. İmza ise
      // damgadan önce atıldığı için etkilenmiyor.
      expect(sonuc.documentTimestamps[0]?.valid).toBe(false)
      expect(sonuc.signatures[0]?.valid).toBe(true)
    })

    it('damga imza olarak sayılmıyor', () => {
      const sonuc = padesVerify(arsiv())
      expect(sonuc.signatures).toHaveLength(1)
      expect(sonuc.documentTimestamps).toHaveLength(1)
    })
  })

  describe('seviye merdiveni', () => {
    it('zaman damgası yoksa seviye B-B', () => {
      expect(padesVerify(imzala().pdf).signatures[0]?.level).toBe('B-B')
    })

    it('imza zaman damgası varsa B-T', () => {
      expect(padesVerify(damgala()).signatures[0]?.level).toBe('B-T')
    })

    /**
     * ETSI, B-LT'nin B-T üzerine kurulmasını şart koşar. İmza zamanı
     * kanıtlanmamışsa "iptal kanıtı imza anında geçerliydi" demek bir şey
     * ifade etmez; bu yüzden DSS tek başına seviyeyi yükseltmiyor.
     */
    it('B-T olmadan DSS eklenirse seviye B-B kalıyor', () => {
      const dsssiz = padesUpgrade({ pdf: imzala().pdf, to: 'LT', ...malzeme() })
      expect(padesVerify(dsssiz).signatures[0]?.level).toBe('B-B')
    })

    it('DSS yoksa damga atılsa bile B-T üstüne çıkmıyor', () => {
      const damgali = arsiv(damgala())
      expect(padesVerify(damgali).signatures[0]?.level).toBe('B-T')
    })

    /**
     * Seviyeyi yükselten şey MALZEMEDİR, `/VRI` değil. `/VRI` yalnızca
     * "hangi kanıt hangi imzaya ait" ipucudur; tek başına hiçbir sertifika
     * ya da iptal kanıtı taşımaz.
     *
     * Ayrım, DSS'teki dizi adları AYNI UZUNLUKTA bozularak kuruluyor:
     * bayt sayısı değişmediği için çapraz başvuru konumları geçerli kalıyor
     * ve belge yalnızca "VRI var, malzeme yok" hâline geliyor.
     */
    it('/VRI var ama malzeme yoksa seviye B-T kalıyor', () => {
      const pdf = uzunDonem()
      const bozuk = kismiDegistir(pdf, [
        ['/Certs', '/Cxrts'],
        ['/OCSPs', '/OxSPs'],
      ])
      const dss = readDocumentSecurityStore(bozuk)
      expect(dss?.certificates).toHaveLength(0)
      expect(dss?.ocspResponses).toHaveLength(0)
      expect(dss?.vriKeys).toHaveLength(1)
      expect(padesVerify(bozuk).signatures[0]?.level).toBe('B-T')
    })

    /**
     * Geçersiz bir damga seviyeyi YÜKSELTMEZ. Aksi hâlde "B-LTA" etiketi,
     * kimsenin denetlemediği bir iddiadan ibaret olurdu.
     */
    it('doğrulanamayan belge damgası seviyeyi B-LTAya çıkarmıyor', () => {
      const material = keyMaterial()
      const baskasi = padesDocumentTimestamp({ pdf: damgala() })
      const jeton = parseTimestampResponse(material.tsa.issue(baskasi.request))

      const bekleyen = padesDocumentTimestamp({ pdf: uzunDonem() })
      const bozuk = bekleyen.finish(jeton, { verifyToken: false })
      const imza = padesVerify(bozuk).signatures[0]
      expect(imza?.level).toBe('B-LT')
      expect(imza?.warnings.map((w) => w.code)).toContain('document-timestamp-invalid')
    })
  })

  describe('poppler pdfsig çapraz doğrulaması', () => {
    it.skipIf(!hasPdfsig)('DSS eklendikten sonra imzayı hâlâ geçerli buluyor', () => {
      expect(pdfsig(uzunDonem())).toContain('Signature is Valid')
    })

    it.skipIf(!hasPdfsig)('belge damgası atıldıktan sonra da imzayı geçerli buluyor', () => {
      expect(pdfsig(arsiv())).toContain('Signature is Valid')
    })

    /**
     * En değerli çapraz kontrol. poppler damgayı ayrı bir imza alanı olarak
     * görüyor ve `/ByteRange`ını KENDİ hesaplayıp "Total document signed"
     * diyor. Bu, damganın kapsamının bizden bağımsız doğrulanması demek —
     * damga alanının yerleşimini yanlış hesaplasaydık burası tutmazdı.
     */
    it.skipIf(!hasPdfsig)('damgayı ikinci bir imza alanı olarak görüp kapsamını onaylıyor', () => {
      const cikti = pdfsig(arsiv())
      expect(cikti).toContain('Signature #2')
      expect(cikti).toContain('Signature Field Name: Damga-')
      // İmza artık tamamını kapsamıyor (üstüne DSS ve damga eklendi),
      // damga ise kapsıyor. İkisi aynı çıktıda görünüyor.
      expect(cikti).toContain('- Not total document signed')
      expect(cikti).toContain('- Total document signed')
    })

    it.skipIf(!hasPdfsig)('bozulmuş LTA belgesini pdfsig de reddediyor', () => {
      expect(pdfsig(bozulmus(arsiv()))).not.toContain('Signature is Valid')
    })
  })

  it('pdfsig bulunmalı — yoksa çapraz doğrulama sessizce atlanır', () => {
    expect(hasPdfsig).toBe(true)
  })
})
