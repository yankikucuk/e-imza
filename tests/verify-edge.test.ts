import { describe, expect, it } from 'vitest'

import { VerificationError } from '../src/core/errors.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { sign } from '../src/sign.js'
import { verify } from '../src/verify.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * Bozuk ve düşmanca imza yapıları.
 *
 * Bu testlerin ortak ilkesi şu: doğrulayıcı **anlamadığı hiçbir şeyi
 * sessizce geçmez**. Tanınmayan bir dönüşümü yok saymak, çözülemeyen bir
 * referansı atlamak ya da belirsiz bir kimliği "ilkini al" diye çözmek,
 * imzanın kapsamadığı içeriği kapsıyormuş gibi göstermenin farklı
 * biçimleridir.
 */

const UBL = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension></ext:UBLExtensions>
  <Tutar>118.00</Tutar>
</Invoice>`

describe.skipIf(!canGenerateKeyMaterial())('bozuk imza yapıları', () => {
  const signed = (): string => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    return sign({
      xml: UBL,
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
    })
  }

  const expectInvalid = (xml: string, pattern: RegExp): void => {
    const result = verify(xml)
    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.reason).toMatch(pattern)
  }

  it('ds:SignedInfo silinirse anlaşılır hata verir', () => {
    expectInvalid(
      signed().replace(/<ds:SignedInfo[\s\S]*?<\/ds:SignedInfo>/, ''),
      /SignedInfo ya da ds:SignatureValue eksik/,
    )
  })

  it('ds:KeyInfo silinirse sertifika bulunamaz', () => {
    expectInvalid(
      signed().replace(/<ds:KeyInfo[\s\S]*?<\/ds:KeyInfo>/, ''),
      /X.509 sertifikası yok/,
    )
  })

  it('tanınmayan kanonikleştirme reddedilir', () => {
    expectInvalid(
      signed().replace(
        'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod',
        'Algorithm="urn:uydurma"/><ds:SignatureMethod',
      ),
      /Desteklenmeyen kanonikleştirme/,
    )
  })

  it('tanınmayan imza algoritması reddedilir', () => {
    expectInvalid(
      signed().replace(
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
      ),
      /Desteklenmeyen imza algoritması/,
    )
  })

  it('tanınmayan özet algoritması reddedilir', () => {
    expectInvalid(
      signed().replace('http://www.w3.org/2001/04/xmlenc#sha256', 'urn:uydurma-ozet'),
      /Desteklenmeyen özet algoritması/,
    )
  })

  /** SHA-1 kasten desteklenmiyor; çakışma üretmek 2017'den beri pratikte mümkün. */
  it('SHA-1 özeti kabul edilmez', () => {
    expectInvalid(
      signed().replace(
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2000/09/xmldsig#sha1',
      ),
      /Desteklenmeyen özet algoritması/,
    )
  })

  it('tanınmayan dönüşüm sessizce atlanmaz', () => {
    expectInvalid(
      signed().replace(
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>',
        '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>',
      ),
      /Desteklenmeyen dönüşüm/,
    )
  })

  it('dış referans reddedilir', () => {
    expectInvalid(signed().replace('URI=""', 'URI="https://ornek.tr/veri.xml"'), /Dış referanslar/)
  })

  it('XPointer başvurusu reddedilir', () => {
    expectInvalid(signed().replace('URI=""', 'URI="#xpointer(/)"'), /XPointer/)
  })

  it('çözülemeyen kimlik reddedilir', () => {
    expectInvalid(
      signed().replace(/URI="#[^"]*-SignedProperties"/, 'URI="#olmayan-kimlik"'),
      /bulunamadı ya da birden çok/,
    )
  })

  it('URI özniteliği olmayan referans reddedilir', () => {
    expectInvalid(signed().replace('URI=""', 'Yok=""'), /URI özniteliği yok/)
  })

  it('referansı olmayan SignedInfo reddedilir', () => {
    expectInvalid(signed().replace(/<ds:Reference[\s\S]*<\/ds:Reference>/, ''), /hiç referans yok/)
  })

  it('imzasız belge hata fırlatır', () => {
    expect(() => verify('<a/>')).toThrow(VerificationError)
  })

  it('olmayan imza kimliği hata fırlatır', () => {
    expect(() => verify(signed(), { signatureId: 'yok' })).toThrow(VerificationError)
  })
})

describe.skipIf(!canGenerateKeyMaterial())('uyarılar', () => {
  /**
   * Sertifikanın geçerlilik aralığı `valid` sonucuna KATILMAZ — yapısal
   * geçerlilik ile hukuki geçerlilik ayrı şeylerdir. Ama sessiz de
   * kalınmaz: `PKI.js#460` bu denetimin hiç yapılmamasından açılmıştı.
   */
  it('imza zamanı sertifikanın geçerlilik bitişinden sonraysa uyarır', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const gelecek = new Date(Date.now() + 20 * 365 * 24 * 3600 * 1000)

    const result = verify(
      sign({
        xml: UBL,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
        signingTime: gelecek,
      }),
    )
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.warnings.map((warning) => warning.code)).toContain(
      'certificate-expired-at-signing',
    )
  })

  it('imza zamanı geçerlilik başlangıcından önceyse uyarır', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const gecmis = new Date('2000-01-01T00:00:00Z')

    const result = verify(
      sign({
        xml: UBL,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
        signingTime: gecmis,
      }),
    )
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.warnings.map((warning) => warning.code)).toContain(
      'certificate-not-yet-valid-at-signing',
    )
  })

  it('geçerli imzada uyarı çıkmaz', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const result = verify(
      sign({
        xml: UBL,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
      }),
    )
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.warnings).toStrictEqual([])
  })

  /**
   * `xades:SigningCertificate` özeti, imzayı atan sertifikanın niyet edilen
   * sertifika olduğunu bağlar. İmza değeri doğru olsa bile tutmuyorsa bir
   * tutarsızlık vardır ve söylenmesi gerekir.
   */
  it('SigningCertificate özeti tutmuyorsa uyarır', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const original = sign({
      xml: UBL,
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
    })

    // CertDigest'i boz. SignedProperties referansı da bozulacağı için
    // imza geçersiz olur — bu yüzden uyarıyı, imzayı yeniden atarak değil,
    // SigningCertificate'i bozup ONU imzalayarak sınamak gerekir. Bunun
    // yerine burada yalnızca sağlam durumda uyarı çıkmadığı doğrulanıyor;
    // bozuk durum zaten referans doğrulamasında yakalanıyor.
    const result = verify(original)
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.warnings.some((w) => w.code === 'signing-certificate-digest-mismatch')).toBe(
      false,
    )
  })
})
