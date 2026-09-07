import { describe, expect, it } from 'vitest'

import { canonicalizeToBytes } from '../src/c14n/canonicalize.js'
import { fromBase64, toHex } from '../src/core/bytes.js'
import { SigningError } from '../src/core/errors.js'
import { buildOcspRequest, parseOcspResponse, verifyOcspResponse } from '../src/pki/ocsp.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { parseTimestampResponse, verifyTimestampToken } from '../src/pki/tsp.js'
import { sign } from '../src/sign.js'
import { archiveTimestampRequest, timestampRequest, upgrade } from '../src/upgrade.js'
import { verify } from '../src/verify.js'
import { archiveTimestampInput } from '../src/xades/archive.js'
import { Namespace } from '../src/xades/constants.js'
import { digest } from '../src/xades/signature.js'
import { childNamed, textContent, walkElements } from '../src/xml/node.js'
import { parseXml } from '../src/xml/parse.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/** `haystack` içinde `needle` bayt dizisi geçiyor mu. */
const icerir = (haystack: Uint8Array, needle: Uint8Array): boolean => {
  if (needle.length === 0 || needle.length > haystack.length) return false
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

const UBL = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension></ext:UBLExtensions>
  <Tutar>1180.00</Tutar>
</Invoice>`

describe.skipIf(!canGenerateKeyMaterial())('XAdES-T yükseltme', () => {
  const imzala = (options: { id?: string } = {}): string => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    return sign({
      xml: UBL,
      signer: { certificate: bundle.certificate, chain: bundle.chain },
      privateKey: bundle.privateKey,
      ...(options.id === undefined ? {} : { id: options.id }),
    })
  }

  /** Doğrulama sonucundan seviyeyi verir; geçersizse hata mesajını. */
  const nokta = (belge: string): string => {
    const sonuc = verify(belge)
    return sonuc.valid ? sonuc.level : `GEÇERSİZ: ${sonuc.reason}`
  }

  /** İmzalı belgeye çevrimdışı TSA'dan alınan jetonu uygular. */
  const damgala = (imzali: string): string => {
    const { tsa } = keyMaterial()
    const token = parseTimestampResponse(tsa.issue(timestampRequest({ xml: imzali })))
    return upgrade({ xml: imzali, to: 'T', token })
  }

  it('imza T seviyesine yükseliyor', () => {
    const imzali = imzala()
    expect(verify(imzali).valid).toBe(true)

    const damgali = damgala(imzali)
    const sonuc = verify(damgali)
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.level).toBe('T')
  })

  /**
   * Yükseltmenin tüm mantığı bu testte. `xades:UnsignedProperties` hiçbir
   * `ds:Reference` tarafından KAPSANMAZ — adı da bunu söylüyor. Belgeye
   * imzadan sonra eklenebilmesinin tek nedeni bu; `SignedProperties`e bir
   * şey eklemek imzayı anında geçersiz kılardı.
   */
  it('yükseltme imzayı bozmuyor — referans özetleri aynen tutuyor', () => {
    const damgali = damgala(imzala())
    const sonuc = verify(damgali)
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.references.every((referans) => referans.valid)).toBe(true)
  })

  it('yükseltmeden sonra belge kurcalanırsa yine düşüyor', () => {
    const damgali = damgala(imzala())
    expect(verify(damgali.replace('1180.00', '9999.00')).valid).toBe(false)
  })

  /**
   * ETSI TS 101 903 §7.3: damgalanan şey **kanonikleştirilmiş
   * `ds:SignatureValue` ÖĞESİDİR** — etiketleri dâhil; içindeki base64
   * metin değil. Bu ayrımı kaçırmak, kendi doğrulayıcınız dışında hiçbir
   * yerde kabul edilmeyen bir jeton üretir.
   */
  it('damgalanan şey kanonikleştirilmiş SignatureValue öğesidir', () => {
    const { tsa } = keyMaterial()
    const imzali = imzala()
    const token = parseTimestampResponse(tsa.issue(timestampRequest({ xml: imzali })))

    const document = parseXml(imzali)
    const signature = [...walkElements(document.root)].find(
      (element) => element.namespace === Namespace.SIGNATURE && element.localName === 'Signature',
    )!
    const value = childNamed(signature, Namespace.SIGNATURE, 'SignatureValue')!
    const kanonik = canonicalizeToBytes(document, { algorithm: 'exc-c14n', subset: value })

    // Öğenin kendisi damgalanmış olmalı.
    const sonuc = verifyTimestampToken(token, { data: kanonik })
    expect(sonuc.valid).toBe(true)

    // Yalnızca içindeki base64 metin DEĞİL.
    const yalnizMetin = new TextEncoder().encode(
      /<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/.exec(imzali)?.[1] ?? '',
    )
    expect(verifyTimestampToken(token, { data: yalnizMetin }).valid).toBe(false)
    expect(toHex(digest('SHA-256', kanonik))).not.toBe(toHex(digest('SHA-256', yalnizMetin)))
  })

  it('yapı ETSI sırasına uygun yerleşiyor', () => {
    const damgali = damgala(imzala())
    const document = parseXml(damgali)
    const qualifying = [...walkElements(document.root)].find(
      (element) => element.localName === 'QualifyingProperties',
    )!

    const isimler = qualifying.children.flatMap((child) =>
      child.kind === 'element' ? [child.localName] : [],
    )
    // xsd:sequence — UnsignedProperties, SignedProperties'ten SONRA gelir.
    expect(isimler).toStrictEqual(['SignedProperties', 'UnsignedProperties'])

    const unsigned = childNamed(qualifying, Namespace.XADES, 'UnsignedProperties')!
    const unsignedSignature = childNamed(unsigned, Namespace.XADES, 'UnsignedSignatureProperties')!
    const timestamp = childNamed(unsignedSignature, Namespace.XADES, 'SignatureTimeStamp')!
    expect(childNamed(timestamp, Namespace.SIGNATURE, 'CanonicalizationMethod')).toBeDefined()
    expect(childNamed(timestamp, Namespace.XADES, 'EncapsulatedTimeStamp')).toBeDefined()
  })

  it('birden çok zaman damgası üst üste eklenebiliyor', () => {
    const bir = damgala(imzala())
    const iki = damgala(bir)

    const document = parseXml(iki)
    const damgalar = [...walkElements(document.root)].filter(
      (element) => element.localName === 'SignatureTimeStamp',
    )
    expect(damgalar).toHaveLength(2)
    expect(verify(iki).valid).toBe(true)
  })

  describe('LT — uzun dönem', () => {
    /**
     * LT'nin amacı: imzayı **sertifikaların süresi dolduktan sonra da**
     * doğrulanabilir kılmak. Doğrulayanın ihtiyaç duyacağı her şey — zincir
     * ve iptal kanıtı — imzanın içine gömülür. Aksi hâlde beş yıl sonra
     * "bu sertifika imza anında iptal edilmiş miydi?" sorusunun cevabı
     * hiçbir yerde bulunamaz; OCSP yanıtlayıcıları geçmişi saklamaz.
     */
    const ltMalzemesi = (): {
      certificates: Uint8Array[]
      ocspResponses: Uint8Array[]
    } => {
      const { modernRsa, intermediateCertificate, rootCertificate, ocsp } = keyMaterial()
      const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
      const yanit = ocsp.respond(
        buildOcspRequest({
          certificate: bundle.certificate,
          issuer: intermediateCertificate,
        }),
      )
      return {
        certificates: [intermediateCertificate, rootCertificate],
        ocspResponses: [yanit],
      }
    }

    it('zincir ve OCSP yanıtı gömülüyor, seviye LT oluyor', () => {
      const damgali = damgala(imzala())
      const lt = upgrade({ xml: damgali, to: 'LT', ...ltMalzemesi() })

      expect(lt).toContain('xades:CertificateValues')
      expect(lt).toContain('xades:EncapsulatedX509Certificate')
      expect(lt).toContain('xades:RevocationValues')
      expect(lt).toContain('xades:EncapsulatedOCSPValue')

      const sonuc = verify(lt)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('LT')
    })

    it('gömülen OCSP yanıtı geri okunup doğrulanabiliyor', () => {
      const { modernRsa, intermediateCertificate } = keyMaterial()
      const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
      const lt = upgrade({ xml: damgala(imzala()), to: 'LT', ...ltMalzemesi() })

      const document = parseXml(lt)
      const gomulu = [...walkElements(document.root)].find(
        (element) => element.localName === 'EncapsulatedOCSPValue',
      )
      expect(gomulu).toBeDefined()
      if (gomulu === undefined) return

      const yanit = parseOcspResponse(fromBase64(textContent(gomulu)))
      const sonuc = verifyOcspResponse(yanit, {
        certificate: bundle.certificate,
        issuer: intermediateCertificate,
      })
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.certificateStatus.status).toBe('good')
    })

    it('LT yükseltmesi imzayı bozmuyor', () => {
      const lt = upgrade({ xml: damgala(imzala()), to: 'LT', ...ltMalzemesi() })
      const sonuc = verify(lt)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.references.every((referans) => referans.valid)).toBe(true)
      expect(sonuc.timestamps[0]?.valid).toBe(true)
    })

    it('yinelenen sertifika bir kez gömülüyor', () => {
      const { certificates, ocspResponses } = ltMalzemesi()
      const lt = upgrade({
        xml: damgala(imzala()),
        to: 'LT',
        certificates: [...certificates, ...certificates],
        ocspResponses,
      })
      expect(lt.match(/<xades:EncapsulatedX509Certificate>/g)).toHaveLength(certificates.length)
    })

    it('CRL de gömülebiliyor', () => {
      const { certificates } = ltMalzemesi()
      // İçerik burada önemli değil; gömme yolunun çalıştığı sınanıyor.
      const lt = upgrade({
        xml: damgala(imzala()),
        to: 'LT',
        certificates,
        crls: [new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])],
      })
      expect(lt).toContain('xades:CRLValues')
      expect(lt).toContain('xades:EncapsulatedCRLValue')
      expect(verify(lt).valid).toBe(true)
    })

    /**
     * Yalnızca zincir gömmek LT değildir: iptal kanıtı olmadan imza,
     * sertifikaların süresi dolduktan sonra yine doğrulanamaz. Sessizce
     * kabul etmek, kullanıcıya sahte bir uzun-dönem güvencesi vermek olurdu.
     */
    it('iptal kanıtı olmadan reddediliyor', () => {
      const { certificates } = ltMalzemesi()
      expect(() => upgrade({ xml: damgala(imzala()), to: 'LT', certificates })).toThrow(
        /iptal kanıtı olmadan anlamsız/,
      )
    })

    it('sertifikasız reddediliyor', () => {
      const { ocspResponses } = ltMalzemesi()
      expect(() =>
        upgrade({ xml: damgala(imzala()), to: 'LT', certificates: [], ocspResponses }),
      ).toThrow(/en az bir sertifika/)
    })

    /**
     * LT, T'nin üstüne oturur. Damgası doğrulanmayan bir imzada
     * `CertificateValues` bulunması seviyeyi LT yapmaz — kanıt zinciri
     * eksik demektir.
     */
    it('doğrulanmış damga yoksa seviye LT olmuyor', () => {
      const lt = upgrade({ xml: imzala(), to: 'LT', ...ltMalzemesi() })
      const sonuc = verify(lt)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('BES')
    })
  })

  describe('LTA — arşiv zaman damgası', () => {
    /**
     * Arşiv damgası imzanın ve o ana kadarki bütün imzalanmamış
     * özelliklerin **tamamını** kapsar. Gerekçesi: LT'de gömdüğünüz OCSP
     * yanıtını imzalayan sertifikanın da bir gün süresi dolar; arşiv
     * damgası o zinciri kırılmadan uzatır.
     *
     * **Sınır:** uygulanan tanım ETSI TS 101 903 v1.4.2 §8.2.1. EN 319 132
     * arşiv damgası için farklı bir girdi tanımlar. Bağımsız bir
     * uygulamayla çapraz doğrulama yapılamadı — zaman damgasının KENDİSİ
     * OpenSSL ile iki yönde sınandı, ama arşiv girdisinin hesabı yalnızca
     * kendi testlerimizle sınanmış durumda.
     */
    const arsivle = (belge: string): string => {
      const { tsa } = keyMaterial()
      const token = parseTimestampResponse(tsa.issue(archiveTimestampRequest({ xml: belge })))
      return upgrade({ xml: belge, to: 'LTA', token })
    }

    const ltMalzeme = (): { certificates: Uint8Array[]; ocspResponses: Uint8Array[] } => {
      const { modernRsa, intermediateCertificate, rootCertificate, ocsp } = keyMaterial()
      const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
      return {
        certificates: [intermediateCertificate, rootCertificate],
        ocspResponses: [
          ocsp.respond(
            buildOcspRequest({
              certificate: bundle.certificate,
              issuer: intermediateCertificate,
            }),
          ),
        ],
      }
    }

    it('tam zincir: imza → T → LT → LTA', () => {
      const imzali = imzala()
      expect(verify(imzali).valid).toBe(true)

      const t = damgala(imzali)
      expect(nokta(t)).toBe('T')

      const lt = upgrade({ xml: t, to: 'LT', ...ltMalzeme() })
      expect(nokta(lt)).toBe('LT')

      const lta = arsivle(lt)
      expect(nokta(lta)).toBe('LTA')
    })

    it('arşiv damgası yapıya doğru yerleşiyor', () => {
      const lta = arsivle(damgala(imzala()))
      expect(lta).toContain('xades141:ArchiveTimeStamp')
      expect(lta).toContain('http://uri.etsi.org/01903/v1.4.1#')

      const document = parseXml(lta)
      const arsiv = [...walkElements(document.root)].find(
        (element) => element.localName === 'ArchiveTimeStamp',
      )
      expect(arsiv).toBeDefined()
      if (arsiv === undefined) return
      expect(arsiv.namespace).toBe('http://uri.etsi.org/01903/v1.4.1#')
      expect(childNamed(arsiv, Namespace.XADES, 'EncapsulatedTimeStamp')).toBeDefined()
    })

    it('arşiv damgası ayrıca raporlanıyor', () => {
      const sonuc = verify(arsivle(damgala(imzala())))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps.map((damga) => damga.kind)).toStrictEqual(['signature', 'archive'])
      expect(sonuc.timestamps.every((damga) => damga.valid)).toBe(true)
    })

    it('arşiv damgası imzayı bozmuyor', () => {
      const sonuc = verify(arsivle(damgala(imzala())))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.references.every((referans) => referans.valid)).toBe(true)
    })

    /**
     * Arşiv damgası, KENDİSİNDEN ÖNCE gelen imzalanmamış özellikleri
     * kapsar. Kapsamasaydı LT verisi damganın dışında kalır ve sonradan
     * değiştirilebilirdi — LTA'nın var oluş nedeni tam olarak bunu
     * engellemek.
     */
    it('LT verisi arşiv damgasının kapsamına giriyor', () => {
      const lt = upgrade({ xml: damgala(imzala()), to: 'LT', ...ltMalzeme() })
      const lta = arsivle(lt)
      expect(verify(lta).valid).toBe(true)

      // Gömülü OCSP yanıtının tek bir base64 karakterini değiştir.
      const base64 = /<xades:EncapsulatedOCSPValue>([\s\S]*?)<\/xades:EncapsulatedOCSPValue>/.exec(
        lta,
      )?.[1]
      expect(base64).toBeDefined()
      if (base64 === undefined) return
      const bozuk = lta.replace(base64, (base64.startsWith('M') ? 'N' : 'M') + base64.slice(1))
      expect(bozuk).not.toBe(lta)

      const sonuc = verify(bozuk)
      // İmza hâlâ geçerli — LT verisi imzalanmamış özellikler altında.
      // Ama ARŞİV damgası artık tutmamalı.
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      const arsiv = sonuc.timestamps.find((damga) => damga.kind === 'archive')
      expect(arsiv?.valid).toBe(false)
      expect(sonuc.level).not.toBe('LTA')
    })

    /**
     * Bu test, LTA'daki asıl riski karşılıyor.
     *
     * Arşiv damgasını hem ÜRETEN hem DOĞRULAYAN biziz. Girdiyi yanlış
     * hesaplasak bile — örneğin `ds:SignatureValue`yu hiç katmasak — iki
     * taraf aynı yanlışı yapacağı için imza-doğrula döngüsü yine geçerdi.
     * Bağımsız bir uygulamayla çapraz doğrulama yapılamadığı için (bkz.
     * modül başlığı) girdinin BİLEŞİMİ doğrudan sabitleniyor.
     *
     * Ölçüldü: bu iddia olmadan, girdiden referans verisini ya da
     * SignatureValue'yu çıkaran mutasyonlar hiçbir testi düşürmüyordu.
     */
    it('arşiv girdisi beklenen parçaların hepsini içeriyor', () => {
      const damgali = damgala(imzala())
      const document = parseXml(damgali)
      const signature = [...walkElements(document.root)].find(
        (element) => element.namespace === Namespace.SIGNATURE && element.localName === 'Signature',
      )!

      const girdi = archiveTimestampInput(document, signature, 'exc-c14n').bytes

      const parca = (localName: string): Uint8Array =>
        canonicalizeToBytes(document, {
          algorithm: 'exc-c14n',
          subset: childNamed(signature, Namespace.SIGNATURE, localName)!,
        })

      // 1. Belge referansının verisi: imza çıkarılmış belgenin kanonik hâli.
      const belgeVerisi = canonicalizeToBytes(document, {
        algorithm: 'exc-c14n',
        omit: new Set([signature]),
      })
      expect(icerir(girdi, belgeVerisi)).toBe(true)

      // 2. SignedInfo, 3. SignatureValue, 4. KeyInfo.
      expect(icerir(girdi, parca('SignedInfo'))).toBe(true)
      expect(icerir(girdi, parca('SignatureValue'))).toBe(true)
      expect(icerir(girdi, parca('KeyInfo'))).toBe(true)

      // 5. O ana kadarki imzalanmamış özellik: zaman damgası.
      const damga = [...walkElements(signature)].find(
        (element) => element.localName === 'SignatureTimeStamp',
      )!
      expect(
        icerir(girdi, canonicalizeToBytes(document, { algorithm: 'exc-c14n', subset: damga })),
      ).toBe(true)
    })

    it('birden çok arşiv damgası üst üste eklenebiliyor', () => {
      const bir = arsivle(damgala(imzala()))
      const iki = arsivle(bir)
      const sonuc = verify(iki)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps.filter((damga) => damga.kind === 'archive')).toHaveLength(2)
      expect(sonuc.timestamps.every((damga) => damga.valid)).toBe(true)
    })

    it('başka bir belgenin arşiv jetonu reddediliyor', () => {
      const { tsa } = keyMaterial()
      const birinci = damgala(imzala({ id: 'A' }))
      const ikinci = damgala(imzala({ id: 'B' }))
      const token = parseTimestampResponse(tsa.issue(archiveTimestampRequest({ xml: birinci })))
      expect(() => upgrade({ xml: ikinci, to: 'LTA', token })).toThrow(/messageImprint eşleşmiyor/)
    })

    it('bozuk arşiv jetonu reddediliyor', () => {
      expect(() =>
        upgrade({
          xml: damgala(imzala()),
          to: 'LTA',
          token: new TextEncoder().encode('jeton değil'),
        }),
      ).toThrow(/doğrulanamadı/)
    })
  })

  describe('doğrulayıcı damgayı gerçekten denetliyor', () => {
    /**
     * Bu grubun tamamı tek bir ilkeyi sınıyor: belgenin kendi hakkındaki
     * İDDİASI seviye belirlemez, kanıt belirler. Yapıya bakıp "T" demek,
     * damganın var oluş amacını ortadan kaldırırdı — herkes belgeye
     * `<xades:SignatureTimeStamp>` yazabilir.
     */
    it('geçerli damga rapor ediliyor', () => {
      const sonuc = verify(damgala(imzala()))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps).toHaveLength(1)
      expect(sonuc.timestamps[0]?.valid).toBe(true)
      expect(sonuc.timestamps[0]?.genTime).toBeInstanceOf(Date)
      expect(sonuc.timestamps[0]?.policyOid).toBe(keyMaterial().tsa.policyOid)
      expect(sonuc.warnings).toStrictEqual([])
    })

    it('başka imzanın jetonu gömülürse seviye yükselmiyor', () => {
      const { tsa } = keyMaterial()
      const birinci = imzala({ id: 'A' })
      const ikinci = imzala({ id: 'B' })
      const yabanci = parseTimestampResponse(tsa.issue(timestampRequest({ xml: birinci })))

      // Bağ denetimini atlayarak yanlış jetonu gömüyoruz — doğrulayıcı yine
      // de kanmamalı.
      const sahte = upgrade({ xml: ikinci, to: 'T', token: yabanci, verifyToken: false })
      const sonuc = verify(sahte)

      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('BES')
      expect(sonuc.timestamps[0]?.valid).toBe(false)
      expect(sonuc.warnings.map((uyari) => uyari.code)).toContain('timestamp-invalid')
    })

    it('jeton baytları bozulursa seviye yükselmiyor', () => {
      const damgali = damgala(imzala())
      const base64 = /<xades:EncapsulatedTimeStamp>([\s\S]*?)<\/xades:EncapsulatedTimeStamp>/.exec(
        damgali,
      )?.[1]
      expect(base64).toBeDefined()
      if (base64 === undefined) return
      const bozuk = damgali.replace(base64, (base64.startsWith('M') ? 'N' : 'M') + base64.slice(1))
      expect(bozuk).not.toBe(damgali)

      const sonuc = verify(bozuk)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('BES')
      expect(sonuc.timestamps[0]?.valid).toBe(false)
    })

    it('jetonsuz SignatureTimeStamp öğesi seviye yükseltmiyor', () => {
      const damgali = damgala(imzala())
      const jetonsuz = damgali.replace(
        /<xades:EncapsulatedTimeStamp>[\s\S]*?<\/xades:EncapsulatedTimeStamp>/,
        '',
      )
      const sonuc = verify(jetonsuz)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('BES')
      expect(sonuc.timestamps[0]?.reason).toContain('EncapsulatedTimeStamp yok')
    })

    it('damgasız imzada liste boş', () => {
      const sonuc = verify(imzala())
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps).toStrictEqual([])
    })

    it('iki damganın ikisi de raporlanıyor', () => {
      const sonuc = verify(damgala(damgala(imzala())))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps).toHaveLength(2)
      expect(sonuc.timestamps.every((damga) => damga.valid)).toBe(true)
    })
  })

  describe('jeton bağlama', () => {
    /**
     * Jetonun BU imzayı damgaladığı doğrulanmazsa, başka bir belgeye ait
     * geçerli bir jeton buraya taşınabilirdi — sessizce yanlış bir "T
     * seviyesi" imza üretmenin en olası yolu.
     */
    it('başka bir imzanın jetonu reddediliyor', () => {
      const { tsa } = keyMaterial()
      const birinci = imzala({ id: 'A' })
      const ikinci = imzala({ id: 'B' })
      const token = parseTimestampResponse(tsa.issue(timestampRequest({ xml: birinci })))

      expect(() => upgrade({ xml: ikinci, to: 'T', token })).toThrow(SigningError)
      expect(() => upgrade({ xml: ikinci, to: 'T', token })).toThrow(/messageImprint eşleşmiyor/)
    })

    it('jeton doğrulaması kapatılabiliyor', () => {
      const { tsa } = keyMaterial()
      const birinci = imzala({ id: 'A' })
      const ikinci = imzala({ id: 'B' })
      const token = parseTimestampResponse(tsa.issue(timestampRequest({ xml: birinci })))

      // Kapatmak yalnızca kenar durumlar için; testin amacı davranışı
      // sabitlemek, önermek değil.
      const zorla = upgrade({ xml: ikinci, to: 'T', token, verifyToken: false })
      expect(zorla).toContain('SignatureTimeStamp')
    })

    it('bozuk jeton reddediliyor', () => {
      const imzali = imzala()
      expect(() =>
        upgrade({ xml: imzali, to: 'T', token: new TextEncoder().encode('jeton değil') }),
      ).toThrow(/doğrulanamadı/)
    })
  })

  describe('hata durumları', () => {
    it('imzasız belge yükseltilemiyor', () => {
      expect(() => timestampRequest({ xml: '<a/>' })).toThrow(/ds:Signature öğesi yok/)
    })

    it('birden çok imzada hangisinin damgalanacağı sorulmalı', () => {
      const bir = imzala({ id: 'A' })
      const { modernEc } = keyMaterial()
      const ec = loadPkcs12(modernEc.p12, modernEc.password)
      const iki = sign({
        xml: bir,
        signer: { certificate: ec.certificate },
        privateKey: ec.privateKey,
        id: 'B',
        parallel: true,
      })
      expect(() => timestampRequest({ xml: iki })).toThrow(/signatureId ile belirtilmeli/)
      expect(() => timestampRequest({ xml: iki, signatureId: 'A' })).not.toThrow()
    })

    it('olmayan imza kimliği açık hata veriyor', () => {
      expect(() => timestampRequest({ xml: imzala(), signatureId: 'yok' })).toThrow(/bulunamadı/)
    })

    it('XAdES olmayan imza yükseltilemiyor', () => {
      const imzali = imzala()
      // QualifyingProperties'i sil: geriye düz XMLDSig kalır.
      const dumduz = imzali.replace(/<ds:Object[\s\S]*?<\/ds:Object>/, '')
      const { tsa } = keyMaterial()
      const token = parseTimestampResponse(tsa.issue(timestampRequest({ xml: dumduz })))
      expect(() => upgrade({ xml: dumduz, to: 'T', token })).toThrow(
        /xades:QualifyingProperties yok/,
      )
    })
  })
})
