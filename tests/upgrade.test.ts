import { describe, expect, it } from 'vitest'

import { canonicalizeToBytes } from '../src/c14n/canonicalize.js'
import { toHex } from '../src/core/bytes.js'
import { SigningError } from '../src/core/errors.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { parseTimestampResponse, verifyTimestampToken } from '../src/pki/tsp.js'
import { sign } from '../src/sign.js'
import { timestampRequest, upgrade } from '../src/upgrade.js'
import { verify } from '../src/verify.js'
import { Namespace } from '../src/xades/constants.js'
import { digest } from '../src/xades/signature.js'
import { childNamed, walkElements } from '../src/xml/node.js'
import { parseXml } from '../src/xml/parse.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

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
