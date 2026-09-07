import { randomUUID } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { utf8 } from '../src/core/bytes.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { complete, prepare, sign, signWithKey } from '../src/sign.js'
import { verify, verifyAll } from '../src/verify.js'
import { TR_POLICY_OID } from '../src/xades/constants.js'
import { digest } from '../src/xades/signature.js'
import { parseXml } from '../src/xml/parse.js'
import { serializeXml } from '../src/xml/serialize.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/** UBL-TR 1.2 fatura iskeleti — imza `ext:ExtensionContent` içine girer. */
const invoice = (id = randomUUID()): string => `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent/>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>TR1.2</cbc:CustomizationID>
  <cbc:ProfileID>TEMELFATURA</cbc:ProfileID>
  <cbc:ID>ABC2026000000001</cbc:ID>
  <cbc:UUID>${id}</cbc:UUID>
  <cbc:IssueDate>2026-09-07</cbc:IssueDate>
  <cbc:InvoiceTypeCode>SATIS</cbc:InvoiceTypeCode>
  <cbc:Note>Ç &amp; Ş &lt; Ğ — Türkçe karakterler</cbc:Note>
  <cbc:DocumentCurrencyCode>TRY</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="VKN">1234567890</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>ÖRNEK SATICI A.Ş.</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="TRY">118.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`

describe.skipIf(!canGenerateKeyMaterial())('imzala ve doğrula', () => {
  const rsa = (): {
    certificate: Uint8Array
    chain: readonly Uint8Array[]
    privateKey: ReturnType<typeof loadPkcs12>['privateKey']
  } => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    return { certificate: bundle.certificate, chain: bundle.chain, privateKey: bundle.privateKey }
  }

  it('UBL uzantısına imza atar ve kendi doğrulayıcımız kabul eder', () => {
    const { certificate, chain, privateKey } = rsa()
    const signed = sign({ xml: invoice(), signer: { certificate, chain }, privateKey })

    expect(signed).toContain('<ds:Signature')
    expect(signed).toContain('xades:SignedProperties')

    const result = verify(signed)
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.level).toBe('BES')
    expect(result.references).toHaveLength(2)
    expect(result.references.every((reference) => reference.valid)).toBe(true)
    expect(result.signer.subjectName).toContain('Ornek Mali Muhur')
    expect(result.signatureAlgorithm).toBe('RSA-SHA256')
  })

  it('imza gerçekten ext:ExtensionContent içine yerleşir', () => {
    const { certificate, privateKey } = rsa()
    const document = parseXml(sign({ xml: invoice(), signer: { certificate }, privateKey }))
    const extensions = document.root.children.find(
      (child) => child.kind === 'element' && child.localName === 'UBLExtensions',
    )
    expect(extensions).toBeDefined()
    expect(serializeXml(document)).toContain('ExtensionContent><ds:Signature')
  })

  it('belge değiştirilirse doğrulama başarısız olur', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({ xml: invoice(), signer: { certificate }, privateKey })
    // Tek bir rakam değişiyor: 118.00 → 119.00.
    const tampered = signed.replace('118.00', '119.00')
    expect(tampered).not.toBe(signed)

    const result = verify(tampered)
    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.reason).toContain('değişmiş')
  })

  it('imza değeri değiştirilirse doğrulama başarısız olur', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({ xml: invoice(), signer: { certificate }, privateKey })
    const match = /<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/.exec(signed)
    expect(match).not.toBeNull()
    const value = match?.[1] ?? ''
    // İlk base64 karakterini değiştir — imza değeri artık aynı değil.
    const changed = (value.startsWith('A') ? 'B' : 'A') + value.slice(1)
    const tampered = signed.replace(value, changed)
    expect(tampered).not.toBe(signed)

    const result = verify(tampered)
    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.reason).toContain('açık anahtarıyla doğrulanmadı')
  })

  it('SignedProperties değiştirilirse doğrulama başarısız olur', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({
      xml: invoice(),
      signer: { certificate },
      privateKey,
      productionPlace: { city: 'İstanbul', country: 'TR' },
    })
    const tampered = signed.replace(
      '<xades:City>İstanbul</xades:City>',
      '<xades:City>Ankara</xades:City>',
    )
    expect(tampered).not.toBe(signed)
    expect(verify(tampered).valid).toBe(false)
  })

  it('EC anahtarla imzalar — ham r‖s biçimi', () => {
    const { modernEc } = keyMaterial()
    const bundle = loadPkcs12(modernEc.p12, modernEc.password)
    const signed = sign({
      xml: invoice(),
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
    })
    const result = verify(signed)
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.signatureAlgorithm).toBe('ECDSA-SHA256')
  })

  it('politika verilince seviye EPES olur', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({
      xml: invoice(),
      signer: { certificate },
      privateKey,
      policy: {
        oid: TR_POLICY_OID.P3,
        digest: { algorithm: 'SHA-256', value: digest('SHA-256', utf8('politika belgesi')) },
        uri: 'https://ornek.gov.tr/politika.pdf',
      },
    })
    const result = verify(signed)
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.level).toBe('EPES')
  })

  it('SigningTime null verilince öğe hiç yazılmaz', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({ xml: invoice(), signer: { certificate }, privateKey, signingTime: null })
    expect(signed).not.toContain('SigningTime')
    expect(verify(signed).valid).toBe(true)
  })

  it('kapsayıcı kanonikleştirmeyle de imzalar', () => {
    const { certificate, privateKey } = rsa()
    const signed = sign({
      xml: invoice(),
      signer: { certificate },
      privateKey,
      canonicalization: 'c14n10',
    })
    const result = verify(signed)
    expect(result.valid).toBe(true)
    if (!result.valid) return
    expect(result.canonicalization).toBe('c14n10')
  })
})

describe.skipIf(!canGenerateKeyMaterial())('ayrık imzalama (kart / HSM / uzak servis)', () => {
  /**
   * `xadesjs#85`, `#133`, `node-signpdf#270` ve `#272` hep aynı şeyi
   * istiyordu: özel anahtara erişilemediğinde imzalanacak baytları alıp
   * sonucu geri koyabilmek. Burada özel anahtar `prepare`'a hiç girmiyor.
   */
  it('prepare/complete ile imza dışarıda üretilebilir', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)

    const pending = prepare({
      xml: invoice(),
      signer: { certificate: bundle.certificate, chain: bundle.chain },
    })

    expect(pending.dataToSign.length).toBeGreaterThan(0)
    expect(pending.digest).toHaveLength(32)
    // RSA kartları `CKM_RSA_PKCS` için DigestInfo ister; hazır veriliyor.
    expect(pending.digestInfo).toBeDefined()
    expect(pending.signatureAlgorithm).toBe('RSA-SHA256')

    // "Dışarıdaki imzalayıcı" — burada yerel anahtar, gerçekte kart.
    const signature = signWithKey(pending, bundle.privateKey)
    const signed = complete(pending, signature)

    expect(verify(signed).valid).toBe(true)
  })

  it("imzalanacak baytlar SignedInfo'nun kanonik hâlidir", () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const pending = prepare({ xml: invoice(), signer: { certificate: bundle.certificate } })
    const text = new TextDecoder().decode(pending.dataToSign)
    expect(text.startsWith('<ds:SignedInfo')).toBe(true)
    expect(text).toContain('SignatureMethod')
    expect(text.endsWith('</ds:SignedInfo>')).toBe(true)
  })

  it('EC anahtarda DigestInfo verilmez', () => {
    const { modernEc } = keyMaterial()
    const bundle = loadPkcs12(modernEc.p12, modernEc.password)
    const pending = prepare({ xml: invoice(), signer: { certificate: bundle.certificate } })
    expect(pending.digestInfo).toBeUndefined()
    expect(pending.signatureAlgorithm).toBe('ECDSA-SHA256')
  })

  it('boş imza değeri reddedilir', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const pending = prepare({ xml: invoice(), signer: { certificate: bundle.certificate } })
    expect(() => complete(pending, new Uint8Array(0))).toThrow(/boş/)
  })
})

describe.skipIf(!canGenerateKeyMaterial())('paralel imza', () => {
  const two = (): {
    first: ReturnType<typeof loadPkcs12>
    second: ReturnType<typeof loadPkcs12>
  } => {
    const { modernRsa, modernEc } = keyMaterial()
    return {
      first: loadPkcs12(modernRsa.p12, modernRsa.password),
      second: loadPkcs12(modernEc.p12, modernEc.password),
    }
  }

  /**
   * Varsayılan davranışın belgelenmesi. `enveloped-signature` dönüşümü,
   * tanımı gereği yalnızca kendi imzasını kapsam dışında bırakır — standart
   * budur. Sonucu şudur: ikinci imza belgeye eklendiğinde birincinin
   * kapsadığı içerik değişir ve birinci imza geçersiz olur.
   *
   * `xadesjs#87` bunu "enveloped dönüşümü tek imza siliyor" diye bildirmişti.
   * Dönüşümü değiştirmek çözüm değil; sorun referans modelinde.
   */
  it('varsayılan kipte ikinci imza birinciyi geçersiz kılar', () => {
    const { first, second } = two()
    const once = sign({
      xml: invoice(),
      signer: { certificate: first.certificate },
      privateKey: first.privateKey,
      id: 'Imza-Birinci',
    })
    expect(verify(once).valid).toBe(true)

    const twice = sign({
      xml: once,
      signer: { certificate: second.certificate },
      privateKey: second.privateKey,
      id: 'Imza-Ikinci',
    })

    expect(verify(twice, { signatureId: 'Imza-Ikinci' }).valid).toBe(true)
    expect(verify(twice, { signatureId: 'Imza-Birinci' }).valid).toBe(false)
  })

  /**
   * Gerçek çözüm: XPath Filter 2.0 ile BÜTÜN imzalar kapsam dışında
   * bırakılır. İmzacılar aynı içeriği imzalar, imzalar birbirinden bağımsız
   * olur.
   */
  it('parallel kipinde iki imza birlikte geçerli kalır', () => {
    const { first, second } = two()
    const once = sign({
      xml: invoice(),
      signer: { certificate: first.certificate },
      privateKey: first.privateKey,
      id: 'Imza-Birinci',
      parallel: true,
    })
    const twice = sign({
      xml: once,
      signer: { certificate: second.certificate },
      privateKey: second.privateKey,
      id: 'Imza-Ikinci',
      parallel: true,
    })

    const results = verifyAll(twice)
    expect(results).toHaveLength(2)
    expect(results.every((result) => result.valid)).toBe(true)
    expect(verify(twice, { signatureId: 'Imza-Birinci' }).valid).toBe(true)
    expect(verify(twice, { signatureId: 'Imza-Ikinci' }).valid).toBe(true)
  })

  it('paralel imzada XPath Filter 2.0 dönüşümü yazılır', () => {
    const { first } = two()
    const signed = sign({
      xml: invoice(),
      signer: { certificate: first.certificate },
      privateKey: first.privateKey,
      parallel: true,
    })
    expect(signed).toContain('http://www.w3.org/2002/06/xmldsig-filter2')
    expect(signed).toContain('Filter="subtract"')
    expect(signed).toContain('//ds:Signature')
    expect(signed).not.toContain('enveloped-signature')
  })

  it('paralel imzada belge bozulursa ikisi de düşer', () => {
    const { first, second } = two()
    const once = sign({
      xml: invoice(),
      signer: { certificate: first.certificate },
      privateKey: first.privateKey,
      id: 'A',
      parallel: true,
    })
    const twice = sign({
      xml: once,
      signer: { certificate: second.certificate },
      privateKey: second.privateKey,
      id: 'B',
      parallel: true,
    })
    const tampered = twice.replace('118.00', '999.00')
    expect(verifyAll(tampered).every((result) => !result.valid)).toBe(true)
  })

  /**
   * Tanınmayan bir XPath ifadesi SESSİZCE yok sayılmaz. Yok saymak,
   * imzanın kapsamadığı içeriği kapsıyormuş gibi göstermek olurdu.
   */
  it('desteklenmeyen XPath süzgeci reddedilir', () => {
    const { first } = two()
    const signed = sign({
      xml: invoice(),
      signer: { certificate: first.certificate },
      privateKey: first.privateKey,
      parallel: true,
    })
    const altered = signed.replace('//ds:Signature', '//ds:KeyInfo')
    const result = verify(altered)
    expect(result.valid).toBe(false)
    if (result.valid) return
    expect(result.reason).toContain('XPath Filter 2.0')
  })
})

describe.skipIf(!canGenerateKeyMaterial())('hata ve uyarı durumları', () => {
  it('imzasız belge açık hata verir', () => {
    expect(() => verify('<a/>')).toThrow(/ds:Signature öğesi yok/)
  })

  it('ext:UBLExtensions yoksa açıklayıcı hata verir', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    expect(() =>
      sign({
        xml: '<Fatura/>',
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
      }),
    ).toThrow(/ext:UBLExtensions/)
  })

  it('enveloped yerleşimi UBL olmayan belgede çalışır', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    const signed = sign({
      xml: '<Belge><Icerik>değer</Icerik></Belge>',
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
      placement: 'enveloped',
    })
    expect(verify(signed).valid).toBe(true)
  })

  it('özet ve imza algoritması çelişirse hata verir', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    expect(() =>
      sign({
        xml: invoice(),
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
        signatureAlgorithm: 'RSA-SHA512',
        digestAlgorithm: 'SHA-256',
      }),
    ).toThrow(/SHA-512 kullanır/)
  })
})
