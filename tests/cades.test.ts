import { execFileSync } from 'node:child_process'
import { sign as nodeSign } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { asOid, asSequence, asSet } from '../src/asn1/der.js'
import {
  contentTypeAttribute,
  messageDigestAttribute,
  signingCertificateAttribute,
} from '../src/cades/attributes.js'
import { SignedAttribute } from '../src/cades/constants.js'
import { cadesPrepare, cadesComplete, cadesSign, cadesSignWithKey } from '../src/cades/sign.js'
import { cadesTimestampRequest, cadesUpgrade } from '../src/cades/upgrade.js'
import { cadesVerify } from '../src/cades/verify.js'
import { toBase64, utf8, wrapBase64 } from '../src/core/bytes.js'
import { buildSignedData, cmsDigest, encodeSignedAttributes } from '../src/pki/cms-build.js'
import { CmsOid, parseCmsSignedData } from '../src/pki/cms.js'
import { buildOcspRequest, parseOcspResponse } from '../src/pki/ocsp.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { parseTimestampResponse } from '../src/pki/tsp.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * CAdES — ikili veri imzası.
 *
 * En değerli test grubu **OpenSSL çapraz doğrulaması**: `openssl cms
 * -verify` bizim ürettiğimiz imzayı kabul ediyorsa, yapı yalnızca "kendi
 * doğrulayıcımızla uyumlu" değil, gerçekten RFC 5652 CMS'tir.
 */

const OPENSSL =
  ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find((p) =>
    existsSync(p),
  ) ?? 'openssl'

const directory = mkdtempSync(join(tmpdir(), 'e-imza-cades-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

/** DER sertifikayı PEM'e çevirir. */
const toPem = (der: Uint8Array): string =>
  `-----BEGIN CERTIFICATE-----\n${wrapBase64(toBase64(der))}\n-----END CERTIFICATE-----\n`

let counter = 0
/** `openssl cms -verify` ile doğrular; hata metnini ya da `null` döner. */
const opensslVerify = (
  cms: Uint8Array,
  content?: Uint8Array,
  trustAnchor?: Uint8Array,
): string | null => {
  counter += 1
  const { intermediateCertificate, rootCertificate } = keyMaterial()
  const sig = join(directory, `sig-${String(counter)}.der`)
  const ca = join(directory, `ca-${String(counter)}.pem`)
  writeFileSync(sig, cms)
  // Kök VE ara sertifika birlikte güven deposuna yazılıyor.
  //
  // Ara sertifikayı `-certfile` ile vermek yeterli DEĞİL: OpenSSL 3.0.13
  // (Ubuntu) onu zincir kurmakta kullanmıyor ve "unable to get local issuer
  // certificate" diyor; 3.6.3 (Homebrew) kullanıyor. Sürüm farkı CI'da
  // yakalandı — yerelde geçen test orada düşmüştü. İkisini birden depoya
  // koymak her sürümde çalışıyor ve testin konusunu değiştirmiyor: konu
  // zincir semantiği değil, yapının CMS olarak okunabildiği ve imzanın
  // tuttuğu.
  writeFileSync(
    ca,
    trustAnchor === undefined
      ? toPem(rootCertificate) + toPem(intermediateCertificate)
      : toPem(trustAnchor),
  )

  const args = [
    'cms',
    '-verify',
    '-in',
    sig,
    '-inform',
    'DER',
    '-CAfile',
    ca,
    // Test sertifikalarında extendedKeyUsage yok; amaç denetimi bu testin
    // konusu DEĞİL. Konu, yapının CMS olarak okunabildiği ve imzanın tuttuğu.
    '-purpose',
    'any',
    '-no_check_time',
    '-out',
    join(directory, `out-${String(counter)}.bin`),
  ]
  if (content !== undefined) {
    const data = join(directory, `data-${String(counter)}.bin`)
    writeFileSync(data, content)
    args.push('-content', data)
  }
  try {
    execFileSync(OPENSSL, args, { stdio: ['ignore', 'ignore', 'pipe'] })
    return null
  } catch (error) {
    const stderr = (error as { stderr?: Buffer }).stderr
    return stderr === undefined ? 'bilinmeyen hata' : stderr.toString('utf8')
  }
}

describe.skipIf(!canGenerateKeyMaterial())('CAdES', () => {
  const veri = utf8('imzalanacak ikili veri — Ç Ş Ğ İ')

  const anahtar = (): ReturnType<typeof loadPkcs12> => {
    const { modernRsa } = keyMaterial()
    return loadPkcs12(modernRsa.p12, modernRsa.password)
  }

  const imzala = (options: Partial<Parameters<typeof cadesSign>[0]> = {}): Uint8Array => {
    const bundle = anahtar()
    return cadesSign({
      data: veri,
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
      ...options,
    })
  }

  it('gömülü imza üretiliyor ve kendi doğrulayıcımız kabul ediyor', () => {
    const sonuc = cadesVerify(imzala())
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.level).toBe('BES')
    expect(sonuc.attached).toBe(true)
    expect(sonuc.signer.subjectName).toContain('Ornek Mali Muhur')
    expect(sonuc.signingTime).toBeInstanceOf(Date)
    expect(sonuc.warnings).toStrictEqual([])
  })

  /**
   * Asıl kanıt bu. `openssl cms -verify` ürettiğimiz yapıyı okuyup imzayı
   * doğrulayabiliyorsa, `signedAttrs` kodlaması, `SET` etiketi dönüşümü,
   * `SignerInfo` alan sırası ve `messageDigest` bağının tamamı doğru
   * demektir. Kendi doğrulayıcımızla test etmek bunların hiçbirini
   * göstermez.
   */
  it('OpenSSL gömülü imzamızı doğruluyor', () => {
    expect(opensslVerify(imzala())).toBeNull()
  })

  it('OpenSSL ayrık imzamızı da doğruluyor', () => {
    expect(opensslVerify(imzala({ attached: false }), veri)).toBeNull()
  })

  it('içerik değiştirilirse OpenSSL de biz de reddediyoruz', () => {
    const imza = imzala({ attached: false })
    const bozuk = utf8('başka veri')
    expect(opensslVerify(imza, bozuk)).not.toBeNull()

    const sonuc = cadesVerify(imza, { content: bozuk })
    expect(sonuc.valid).toBe(false)
    if (sonuc.valid) return
    expect(sonuc.reason).toContain('messageDigest')
  })

  it('ayrık imzada içerik verilmezse açık hata veriliyor', () => {
    const sonuc = cadesVerify(imzala({ attached: false }))
    expect(sonuc.valid).toBe(false)
    if (sonuc.valid) return
    expect(sonuc.reason).toContain('içerik verilmedi')
  })

  it('SHA-384 ve SHA-512 ile de imzalanıyor', () => {
    for (const digest of ['sha384', 'sha512'] as const) {
      const imza = imzala({ digest })
      expect(cadesVerify(imza).valid).toBe(true)
      expect(opensslVerify(imza)).toBeNull()
    }
  })

  it('EC anahtarla imzalanıyor — CMS DER imza ister', () => {
    const { modernEc } = keyMaterial()
    const bundle = loadPkcs12(modernEc.p12, modernEc.password)
    const imza = cadesSign({
      data: veri,
      signer: { certificate: bundle.certificate },
      privateKey: bundle.privateKey,
    })
    // XAdES ham r‖s isterken CMS DER ister. OpenSSL EC imzamızı
    // doğrulayabiliyorsa doğru biçimi ürettik demektir. EC sertifikası
    // öz-imzalı olduğu için güven kökü kendisi.
    expect(cadesVerify(imza).valid).toBe(true)
    expect(opensslVerify(imza, undefined, bundle.certificate)).toBeNull()
  })

  describe('imzalanmış öznitelikler', () => {
    it('politika verilince seviye EPES oluyor', () => {
      const imza = imzala({
        policy: {
          oid: '2.16.792.1.61.0.1.5070.3.2.1',
          digest: { algorithm: 'sha256', value: cmsDigest('sha256', utf8('politika')) },
        },
      })
      const sonuc = cadesVerify(imza)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('EPES')
      expect(opensslVerify(imza)).toBeNull()
    })

    it('ima edilen politika da kabul ediliyor', () => {
      const sonuc = cadesVerify(imzala({ policy: 'implied' }))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('EPES')
    })

    it('taahhüt türü ve imzalayan yeri yazılıyor', () => {
      const imza = imzala({
        commitmentType: 'proof-of-origin',
        signerLocation: { country: 'TR', locality: 'İstanbul' },
      })
      expect(cadesVerify(imza).valid).toBe(true)
      expect(opensslVerify(imza)).toBeNull()
    })

    it('signingTime null verilince öznitelik yazılmıyor', () => {
      const sonuc = cadesVerify(imzala({ signingTime: null }))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.signingTime).toBeUndefined()
    })

    /**
     * `signingCertificateV2` CAdES-BES'i düz CMS'ten ayıran özniteliktir.
     * Olmadan imzalayan sertifika yapının içinde değiştirilebilir —
     * doğrulayıcı bunu sessizce geçmiyor, seviyeyi CMS'e düşürüp uyarıyor.
     */
    it('signingCertificate yoksa seviye CMS oluyor ve uyarı çıkıyor', () => {
      // OpenSSL'in kendi CMS imzası bu özniteliği yazmaz.
      const data = join(directory, 'openssl-veri.bin')
      const key = join(directory, 'openssl.key')
      const crt = join(directory, 'openssl.crt')
      const out = join(directory, 'openssl.p7s')
      writeFileSync(data, veri)
      // prettier-ignore
      execFileSync(OPENSSL, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-days', '365', '-keyout', key, '-out', crt, '-subj', '/CN=OpenSSL Imzaci'])
      // `openssl cms -sign` varsayılan olarak AYRIK imza üretir; içeriği
      // gömmesi için `-nodetach` gerekiyor.
      // prettier-ignore
      execFileSync(OPENSSL, ['cms', '-sign', '-in', data, '-signer', crt, '-inkey', key,
        '-outform', 'DER', '-out', out, '-md', 'sha256', '-nodetach'])

      const sonuc = cadesVerify(new Uint8Array(readFileSync(out)))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('CMS')
      expect(sonuc.warnings.map((uyari) => uyari.code)).toContain(
        'no-signing-certificate-attribute',
      )
    })
  })

  describe('sertifika bağı', () => {
    /**
     * `signingCertificateV2` CAdES-BES'in tam kalbi: imzalayan sertifikayı
     * imzaya bağlar. Bağ denetlenmezse, imzayı doğrulayan sertifika ile
     * imzacının BEYAN ETTİĞİ sertifika farklı olabilir ve kimse fark etmez.
     *
     * Ölçüldü: bu test eklenmeden önce, bağ denetimini "her zaman doğru"
     * yapan bir mutasyon hiçbir testi düşürmüyordu.
     *
     * Tutarsız yapı düşük seviyeli parçalarla elle kuruluyor: imza A
     * sertifikasıyla atılıyor ama `signingCertificateV2` B'nin özetini
     * taşıyor.
     */
    it('beyan edilen sertifika imzalayanla eşleşmezse uyarı çıkıyor', () => {
      const bundle = anahtar()
      const { modernEc } = keyMaterial()
      const yabanci = loadPkcs12(modernEc.p12, modernEc.password).certificate

      const attributes = [
        contentTypeAttribute(CmsOid.DATA),
        messageDigestAttribute(cmsDigest('sha256', veri)),
        // YANLIŞ sertifikanın özeti.
        signingCertificateAttribute(yabanci, 'sha256'),
      ]
      const signedAttributes = encodeSignedAttributes(attributes)
      const signature = new Uint8Array(
        nodeSign('sha256', Buffer.from(signedAttributes), bundle.privateKey),
      )
      const cms = buildSignedData({
        content: veri,
        certificate: bundle.certificate,
        digest: 'sha256',
        keyKind: 'rsa',
        signedAttributes,
        signature,
      })

      // İmza kriptografik olarak GEÇERLİ — OpenSSL de kabul ediyor.
      expect(opensslVerify(cms)).toBeNull()

      // Ama beyan edilen sertifika imzalayanla eşleşmiyor.
      const sonuc = cadesVerify(cms)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.warnings.map((uyari) => uyari.code)).toContain(
        'signing-certificate-digest-mismatch',
      )
    })

    it('doğru sertifikayla uyarı çıkmıyor', () => {
      const sonuc = cadesVerify(imzala())
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.warnings.map((uyari) => uyari.code)).not.toContain(
        'signing-certificate-digest-mismatch',
      )
    })

    /**
     * RFC 5652 §11.3: 1950–2049 arasındaki tarihler `UTCTime` olarak
     * kodlanmak ZORUNDA. `GeneralizedTime` yazmak bugünün tarihleri için
     * standart dışıdır; OpenSSL hoşgörülü davranıyor ama katı bir
     * doğrulayıcı reddeder.
     */
    it('signingTime UTCTime olarak kodlanıyor', () => {
      const cms = imzala()
      const signer = parseCmsSignedData(cms).signerInfos[0]
      expect(signer).toBeDefined()
      if (signer === undefined) return

      const zaman = signer.signedAttributes?.find((attribute) => {
        const fields = asSequence(attribute)
        const oid = fields[0]
        return oid !== undefined && asOid(oid) === SignedAttribute.SIGNING_TIME
      })
      expect(zaman).toBeDefined()
      if (zaman === undefined) return

      const deger = asSet(asSequence(zaman)[1]!)[0]
      // 23 = UTCTime, 24 = GeneralizedTime.
      expect(deger?.tagNumber).toBe(23)
    })
  })

  describe('ayrık imzalama', () => {
    it('prepare/complete ile imza dışarıda üretiliyor', () => {
      const bundle = anahtar()
      const bekleyen = cadesPrepare({
        data: veri,
        signer: { certificate: bundle.certificate },
      })

      expect(bekleyen.dataToSign.length).toBeGreaterThan(0)
      // İmzalanan şey `signedAttrs`ın SET etiketli kodlaması.
      expect(bekleyen.dataToSign[0]).toBe(0x31)
      expect(bekleyen.digestInfo).toBeDefined()
      expect(bekleyen.keyKind).toBe('rsa')

      const imza = cadesComplete(bekleyen, cadesSignWithKey(bekleyen, bundle.privateKey))
      expect(cadesVerify(imza).valid).toBe(true)
      expect(opensslVerify(imza)).toBeNull()
    })

    it('boş imza değeri reddediliyor', () => {
      const bundle = anahtar()
      const bekleyen = cadesPrepare({ data: veri, signer: { certificate: bundle.certificate } })
      expect(() => cadesComplete(bekleyen, new Uint8Array(0))).toThrow(/boş/)
    })
  })

  describe('seviye yükseltme', () => {
    const damgala = (imza: Uint8Array): Uint8Array => {
      const { tsa } = keyMaterial()
      const token = parseTimestampResponse(tsa.issue(cadesTimestampRequest({ cms: imza })))
      return cadesUpgrade({ cms: imza, to: 'T', token })
    }

    it('T seviyesine yükseliyor ve imza bozulmuyor', () => {
      const imza = imzala()
      const damgali = damgala(imza)

      const sonuc = cadesVerify(damgali)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('T')
      expect(sonuc.timestamps[0]?.valid).toBe(true)
      expect(sonuc.timestamps[0]?.genTime).toBeInstanceOf(Date)

      // Yükseltme `unsignedAttrs`a yazıyor; imza hâlâ OpenSSL'e göre geçerli.
      expect(opensslVerify(damgali)).toBeNull()
    })

    it('LT seviyesine yükseliyor', () => {
      const { intermediateCertificate, rootCertificate, ocsp } = keyMaterial()
      const bundle = anahtar()
      const ham = ocsp.respond(
        buildOcspRequest({
          certificate: bundle.certificate,
          issuer: intermediateCertificate,
        }),
      )
      const lt = cadesUpgrade({
        cms: damgala(imzala()),
        to: 'LT',
        certificates: [intermediateCertificate, rootCertificate],
        ocspResponses: [parseOcspResponse(ham).der],
      })

      const sonuc = cadesVerify(lt)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('LT')
      expect(opensslVerify(lt)).toBeNull()
    })

    it('başka bir imzanın jetonu reddediliyor', () => {
      const { tsa } = keyMaterial()
      const birinci = imzala()
      const ikinci = imzala({ signingTime: new Date(Date.now() - 3600_000) })
      const token = parseTimestampResponse(tsa.issue(cadesTimestampRequest({ cms: birinci })))
      expect(() => cadesUpgrade({ cms: ikinci, to: 'T', token })).toThrow(
        /messageImprint eşleşmiyor/,
      )
    })

    it('iptal kanıtı olmadan LT reddediliyor', () => {
      const { intermediateCertificate } = keyMaterial()
      expect(() =>
        cadesUpgrade({
          cms: imzala(),
          to: 'LT',
          certificates: [intermediateCertificate],
        }),
      ).toThrow(/iptal kanıtı olmadan anlamsız/)
    })

    it('üst üste iki zaman damgası eklenebiliyor', () => {
      const iki = damgala(damgala(imzala()))
      const sonuc = cadesVerify(iki)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.timestamps.filter((damga) => damga.kind === 'signature')).toHaveLength(2)
    })
  })

  describe('yapı', () => {
    it('gömülü imzada içerik, ayrıkta yok', () => {
      expect(parseCmsSignedData(imzala()).content).toBeDefined()
      expect(parseCmsSignedData(imzala({ attached: false })).content).toBeUndefined()
    })

    it('zincir yapıya giriyor', () => {
      const bundle = anahtar()
      const { intermediateCertificate } = keyMaterial()
      const imza = cadesSign({
        data: veri,
        signer: { certificate: bundle.certificate, chain: [intermediateCertificate] },
        privateKey: bundle.privateKey,
      })
      expect(parseCmsSignedData(imza).certificates).toHaveLength(2)
    })
  })
})
