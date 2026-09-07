import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { canonicalize } from '../c14n/canonicalize.js'
import { toBase64, utf8 } from '../core/bytes.js'
import { serializeElement } from '../xml/serialize.js'

import { TR_POLICY_OID } from './constants.js'
import {
  buildKeyInfo,
  buildSignedProperties,
  deriveIds,
  digest,
  formatSigningTime,
  parallelTransforms,
} from './signature.js'

/**
 * `xades:SignedProperties` yapısının biçimi.
 *
 * Testler serileştirilmiş metne bakıyor: XAdES şeması `xsd:sequence` olduğu
 * için öğe SIRASI geçerliliğin parçasıdır. Sıra yanlışsa imza kriptografik
 * olarak doğru olsa bile şema doğrulamasından geçmez.
 */

const directory = mkdtempSync(join(tmpdir(), 'e-imza-cert-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

/** Testler için tek seferlik bir sertifika üretir. */
const certificate = ((): Uint8Array => {
  const binary =
    ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find(
      (path) => {
        try {
          execFileSync(path, ['version'], { stdio: 'ignore' })
          return true
        } catch {
          return false
        }
      },
    ) ?? 'openssl'
  const key = join(directory, 'k.pem')
  const crt = join(directory, 'c.der')
  execFileSync(binary, [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-sha256',
    '-days',
    '365',
    '-keyout',
    key,
    '-outform',
    'DER',
    '-out',
    crt,
    '-subj',
    '/C=TR/O=Ornek A.S./CN=Ornek Muhur/serialNumber=1234567890',
  ])
  return new Uint8Array(readFileSync(crt))
})()

const ids = deriveIds('S1')

const properties = (overrides: Partial<Parameters<typeof buildSignedProperties>[0]> = {}): string =>
  serializeElement(
    buildSignedProperties({
      ids,
      certificate,
      digestAlgorithm: 'SHA-256',
      signingTime: new Date('2026-09-07T10:00:00Z'),
      ...overrides,
    }),
  )

describe('SignedProperties biçimi', () => {
  it('temel yapı ve öğe sırası', () => {
    const xml = properties()
    expect(xml).toContain('<xades:SignedProperties Id="S1-SignedProperties">')
    expect(xml.indexOf('<xades:SigningTime>')).toBeLessThan(
      xml.indexOf('<xades:SigningCertificate>'),
    )
    expect(xml).toContain('<xades:SigningTime>2026-09-07T10:00:00Z</xades:SigningTime>')
  })

  /** Ondalık — onaltılık değil. `xadesjs#52`. */
  it('seri numarası ondalık yazılır', () => {
    const xml = properties()
    const serial = /<ds:X509SerialNumber>(\d+)<\/ds:X509SerialNumber>/.exec(xml)?.[1]
    expect(serial).toBeDefined()
    expect(/^\d+$/.test(serial ?? '')).toBe(true)
  })

  it('düzenleyen adı RFC 4514 biçiminde ve ters sırada', () => {
    const xml = properties()
    const issuer = /<ds:X509IssuerName>([^<]*)<\/ds:X509IssuerName>/.exec(xml)?.[1] ?? ''
    // Kaynak sıra C, O, CN, SERIALNUMBER; dizede ters okunur.
    expect(issuer.startsWith('SERIALNUMBER=1234567890,CN=Ornek Muhur')).toBe(true)
    expect(issuer.endsWith('C=TR')).toBe(true)
  })

  it('sertifika özeti gerçekten sertifikanın özeti', () => {
    const xml = properties()
    const value = /<xades:CertDigest>[\s\S]*?<ds:DigestValue>([^<]+)</.exec(xml)?.[1]
    expect(value).toBe(toBase64(digest('SHA-256', certificate)))
  })

  it('SigningTime null verilince öğe hiç yazılmaz', () => {
    expect(properties({ signingTime: null })).not.toContain('SigningTime')
  })

  it('üretim yeri alanları isteğe bağlı', () => {
    expect(properties({ productionPlace: { city: 'İstanbul' } })).toContain(
      '<xades:City>İstanbul</xades:City>',
    )
    const full = properties({
      productionPlace: {
        city: 'İstanbul',
        stateOrProvince: 'Marmara',
        postalCode: '34000',
        country: 'TR',
      },
    })
    expect(full).toContain('<xades:StateOrProvince>Marmara</xades:StateOrProvince>')
    expect(full).toContain('<xades:PostalCode>34000</xades:PostalCode>')
    expect(full).toContain('<xades:CountryName>TR</xades:CountryName>')
  })

  it('imzalayan rolleri yazılır', () => {
    const xml = properties({ signerRole: { claimed: ['Mali Müşavir', 'Yetkili'] } })
    expect(xml).toContain('<xades:ClaimedRole>Mali Müşavir</xades:ClaimedRole>')
    expect(xml).toContain('<xades:ClaimedRole>Yetkili</xades:ClaimedRole>')
  })

  it('taahhüt türü OID olarak yazılır', () => {
    expect(properties({ commitmentType: 'proof-of-origin' })).toContain(
      'urn:oid:1.2.840.113549.1.9.16.6.1',
    )
    expect(properties({ commitmentType: 'proof-of-receipt' })).toContain(
      'urn:oid:1.2.840.113549.1.9.16.6.2',
    )
  })

  describe('imza politikası', () => {
    it('ima edilen politika özet istemez', () => {
      const xml = properties({ policy: 'implied' })
      expect(xml).toContain('<xades:SignaturePolicyImplied/>')
      expect(xml).not.toContain('SigPolicyHash')
    })

    it('açık politika OID, özet ve adres taşır', () => {
      const xml = properties({
        policy: {
          oid: TR_POLICY_OID.P3,
          digest: { algorithm: 'SHA-256', value: digest('SHA-256', utf8('politika')) },
          uri: 'https://ornek.gov.tr/p.pdf',
          description: 'Yapılandırılmış veri profili',
        },
      })
      expect(xml).toContain(`urn:oid:${TR_POLICY_OID.P3}`)
      expect(xml).toContain('<xades:Description>Yapılandırılmış veri profili</xades:Description>')
      expect(xml).toContain('<xades:SPURI>https://ornek.gov.tr/p.pdf</xades:SPURI>')
    })

    it('adres ve açıklama isteğe bağlı', () => {
      const xml = properties({
        policy: {
          oid: TR_POLICY_OID.P2,
          digest: { algorithm: 'SHA-512', value: digest('SHA-512', utf8('p')) },
        },
      })
      expect(xml).not.toContain('SigPolicyQualifiers')
      expect(xml).not.toContain('Description')
      expect(xml).toContain('http://www.w3.org/2001/04/xmlenc#sha512')
    })
  })
})

describe('kimlik türetimi', () => {
  /** `ds:SignatureValue` kimliği XAdES-T'nin ön koşulu — `xadesjs#142`, `#143`. */
  it('SignatureValue kimlik alır', () => {
    expect(ids.signatureValue).toBe('S1-SignatureValue')
  })

  it('tüm kimlikler tek kökten türer ve benzersizdir', () => {
    const values: string[] = Object.values(ids)
    expect(new Set(values).size).toBe(values.length)
    expect(values.every((value) => value.startsWith('S1'))).toBe(true)
  })
})

describe('KeyInfo', () => {
  it('zincir varsa hepsi yazılır', () => {
    const xml = serializeElement(buildKeyInfo(ids, certificate, [certificate]))
    expect(xml.match(/<ds:X509Certificate>/g)).toHaveLength(2)
  })

  it('zincir yoksa yalnızca uç sertifika yazılır', () => {
    const xml = serializeElement(buildKeyInfo(ids, certificate, []))
    expect(xml.match(/<ds:X509Certificate>/g)).toHaveLength(1)
  })

  it('base64 satırlara bölünür', () => {
    const xml = serializeElement(buildKeyInfo(ids, certificate, []))
    expect(xml).toContain('\n')
  })
})

describe('zaman biçimi', () => {
  it('salise kısmı atılır', () => {
    expect(formatSigningTime(new Date('2026-09-07T10:00:00.123Z'))).toBe('2026-09-07T10:00:00Z')
  })
})

describe('paralel dönüşüm', () => {
  it('XPath Filter 2.0 süzgeci ve kanonikleştirme üretir', () => {
    const transforms = parallelTransforms('exc-c14n')
    expect(transforms).toHaveLength(2)
    expect(transforms[0]?.algorithm).toBe('http://www.w3.org/2002/06/xmldsig-filter2')
    expect(transforms[1]?.algorithm).toBe('http://www.w3.org/2001/10/xml-exc-c14n#')

    const xpath = transforms[0]?.children?.[0]
    expect(xpath).toBeDefined()
    if (xpath?.kind !== 'element') return
    expect(
      canonicalize(
        { kind: 'document', root: xpath, prolog: [], epilog: [] },
        { algorithm: 'c14n10' },
      ),
    ).toContain('Filter="subtract"')
  })
})
