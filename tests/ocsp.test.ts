import { randomBytes } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { toHex } from '../src/core/bytes.js'
import { DerParseError } from '../src/core/errors.js'
import {
  caIssuerUrls,
  certificateExtension,
  crlDistributionUrls,
  ocspResponderUrls,
} from '../src/pki/extensions.js'
import { buildOcspRequest, parseOcspResponse, verifyOcspResponse } from '../src/pki/ocsp.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * OCSP — çift yönlü sınama, ağsız.
 *
 * Çevrimdışı bir OpenSSL yanıtlayıcısı kullanılıyor. İki yön birden
 * kanıtlanıyor: ürettiğimiz `OCSPRequest`'i OpenSSL okuyup imzalı yanıt
 * üretebiliyor, ve OpenSSL'in ürettiği yanıtı bizim doğrulayıcımız kabul
 * ediyor.
 */

describe.skipIf(!canGenerateKeyMaterial())('OCSP', () => {
  const malzeme = (): { leaf: Uint8Array; issuer: Uint8Array } => {
    const { modernRsa, intermediateCertificate } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    return { leaf: bundle.certificate, issuer: intermediateCertificate }
  }

  it('ürettiğimiz isteği yanıtlayıcı okuyor ve imzalı yanıt veriyor', () => {
    const { ocsp } = keyMaterial()
    const { leaf, issuer } = malzeme()
    const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))
    expect(yanit.responses).toHaveLength(1)
    expect(yanit.signature.length).toBeGreaterThan(0)
  })

  it('geçerli sertifika için "good" dönüyor ve doğrulanıyor', () => {
    const { ocsp } = keyMaterial()
    const { leaf, issuer } = malzeme()
    const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))

    const sonuc = verifyOcspResponse(yanit, { certificate: leaf, issuer })
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.certificateStatus.status).toBe('good')
    expect(sonuc.thisUpdate).toBeInstanceOf(Date)
    expect(sonuc.nextUpdate).toBeInstanceOf(Date)
  })

  it('iptal edilmiş sertifika için "revoked" ve iptal tarihi dönüyor', () => {
    const { ocsp } = keyMaterial()
    const { leaf, issuer } = malzeme()
    const yanit = parseOcspResponse(
      ocsp.respond(buildOcspRequest({ certificate: leaf, issuer }), true),
    )

    const sonuc = verifyOcspResponse(yanit, { certificate: leaf, issuer })
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.certificateStatus.status).toBe('revoked')
    if (sonuc.certificateStatus.status !== 'revoked') return
    expect(sonuc.certificateStatus.revokedAt).toBeInstanceOf(Date)
    // OpenSSL dizin dosyasında keyCompromise = 1.
    expect(sonuc.certificateStatus.reason).toBe(1)
  })

  /**
   * `CertID`nin iki özeti sıkça karıştırılır ve karıştırıldığında
   * yanıtlayıcı sessizce "unknown" döner — hata vermez. Bu test yanlış
   * düzenleyenle sorulduğunda durumun "unknown" olduğunu sabitliyor.
   */
  it('yanlış düzenleyenle sorulunca yanıtlayıcı "unknown" diyor', () => {
    const { ocsp, rootCertificate } = keyMaterial()
    const { leaf } = malzeme()
    // Kök CA, uç sertifikanın düzenleyeni DEĞİL.
    const yanit = parseOcspResponse(
      ocsp.respond(buildOcspRequest({ certificate: leaf, issuer: rootCertificate })),
    )
    expect(yanit.responses[0]?.status.status).toBe('unknown')
  })

  it('yanıt başka bir sertifikaya aitse reddediliyor', () => {
    const { ocsp, rootCertificate } = keyMaterial()
    const { leaf, issuer } = malzeme()
    const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))

    // Doğrulamada BAŞKA bir sertifika sorulursa CertID tutmamalı.
    const sonuc = verifyOcspResponse(yanit, { certificate: rootCertificate, issuer })
    expect(sonuc.valid).toBe(false)
    if (sonuc.valid) return
    expect(sonuc.reason).toContain('CertID eşleşmiyor')
  })

  describe('tek kullanımlık değer', () => {
    it('istekte gönderilen değer yanıtta geri geliyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const nonce = new Uint8Array(randomBytes(16))
      const yanit = parseOcspResponse(
        ocsp.respond(buildOcspRequest({ certificate: leaf, issuer, nonce })),
      )
      expect(yanit.nonce).toBeDefined()
      expect(toHex(yanit.nonce ?? new Uint8Array(0))).toBe(toHex(nonce))
      expect(verifyOcspResponse(yanit, { certificate: leaf, issuer, nonce }).valid).toBe(true)
    })

    it('farklı bir değerle doğrulama reddediliyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const nonce = new Uint8Array(randomBytes(16))
      const yanit = parseOcspResponse(
        ocsp.respond(buildOcspRequest({ certificate: leaf, issuer, nonce })),
      )
      const sonuc = verifyOcspResponse(yanit, {
        certificate: leaf,
        issuer,
        nonce: new Uint8Array(16),
      })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('aynı değil')
    })

    it('yanıtta hiç yoksa tekrar oynatma şüphesi bildiriliyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))
      const sonuc = verifyOcspResponse(yanit, {
        certificate: leaf,
        issuer,
        nonce: new Uint8Array(8),
      })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('tekrar oynatılmış')
    })
  })

  describe('tazelik', () => {
    it('süresi dolmuş yanıt reddediliyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))
      // Yanıt 60 dakika geçerli; iki gün sonra sorulursa geçersiz olmalı.
      const sonra = new Date(Date.now() + 2 * 24 * 3600 * 1000)
      const sonuc = verifyOcspResponse(yanit, { certificate: leaf, issuer, at: sonra })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('süresi dolmuş')
    })

    it('geçerlilik başlangıcı gelecekte olan yanıt reddediliyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))
      const once = new Date(Date.now() - 2 * 24 * 3600 * 1000)
      const sonuc = verifyOcspResponse(yanit, { certificate: leaf, issuer, at: once })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('gelecekte')
    })
  })

  describe('özet algoritması', () => {
    /**
     * `CertID` özeti bir GÜVENLİK özeti değil, bir ADLANDIRMA özeti:
     * yanıtlayıcının hangi sertifikanın sorulduğunu bulmasına yarıyor.
     * RFC 6960 SHA-1 desteğini şart koşuyor ve sahadaki yanıtlayıcılar
     * ezici çoğunlukla başka bir şey kabul etmiyor — bu yüzden varsayılan
     * SHA-1 ve bu, paketin "SHA-1 yok" ilkesinin bilinçli istisnası.
     */
    it('varsayılan SHA-1 ile yanıtlayıcı sertifikayı tanıyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const yanit = parseOcspResponse(ocsp.respond(buildOcspRequest({ certificate: leaf, issuer })))
      expect(yanit.responses[0]?.certId.hashAlgorithm).toBe('sha1')
      expect(yanit.responses[0]?.status.status).toBe('good')
    })

    it('SHA-256 istenirse istek yine geçerli kodlanıyor', () => {
      const { ocsp } = keyMaterial()
      const { leaf, issuer } = malzeme()
      const yanit = parseOcspResponse(
        ocsp.respond(buildOcspRequest({ certificate: leaf, issuer, hashAlgorithm: 'sha256' })),
      )
      expect(yanit.responses[0]?.certId.hashAlgorithm).toBe('sha256')
      // Doğrulama tarafı da aynı algoritmayla yeniden hesaplıyor.
      expect(verifyOcspResponse(yanit, { certificate: leaf, issuer }).valid).toBe(true)
    })
  })

  describe('bozuk girdi', () => {
    it('OCSP olmayan baytlar reddediliyor', () => {
      expect(() => parseOcspResponse(new TextEncoder().encode('yanıt değil'))).toThrow(
        DerParseError,
      )
    })
  })
})

describe.skipIf(!canGenerateKeyMaterial())('sertifika uzantıları', () => {
  /**
   * İptal verisinin nereden alınacağı sertifikanın kendi içinde yazılıdır.
   * Test sertifikalarımızda AIA ve CDP uzantıları yok — bu yüzden burada
   * sınanan şey "adres bulunuyor" değil, "uzantı yoksa boş dönüyor ve
   * çökmüyor".
   */
  it('uzantı yoksa boş liste dönüyor, hata değil', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    expect(ocspResponderUrls(bundle.certificate)).toStrictEqual([])
    expect(crlDistributionUrls(bundle.certificate)).toStrictEqual([])
    expect(caIssuerUrls(bundle.certificate)).toStrictEqual([])
  })

  it('var olan bir uzantı okunabiliyor', () => {
    const { intermediateCertificate } = keyMaterial()
    // Ara CA'ya basicConstraints uzantısı açıkça yazılmıştı.
    expect(certificateExtension(intermediateCertificate, '2.5.29.19')).toBeDefined()
    expect(certificateExtension(intermediateCertificate, '1.2.3.4.5')).toBeUndefined()
  })
})
