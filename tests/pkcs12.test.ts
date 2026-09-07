import { X509Certificate } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { Pkcs12Error } from '../src/core/errors.js'
import { loadPkcs12, selectLeafCertificate } from '../src/pki/pkcs12.js'

import { canGenerateKeyMaterial, hasLegacyOpenssl, keyMaterial } from './key-material.js'

describe.skipIf(!canGenerateKeyMaterial())('PKCS#12 kap okuma', () => {
  it('OpenSSL 3 varsayılanını (PBES2 + AES-256) açar', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    expect(bundle.privateKey.asymmetricKeyType).toBe('rsa')
    expect(new X509Certificate(Buffer.from(bundle.certificate)).subject).toContain(
      'Ornek Mali Muhur',
    )
  })

  /**
   * Paketin var oluş nedenlerinden biri. LibreSSL — ve onunla aynı biçimi
   * yazan eski Java/Windows araçları — sertifika bölümünü
   * `pbeWithSHAAnd40BitRC2-CBC` ile şifreler. Node'un OpenSSL 3'ünde RC2
   * varsayılan sağlayıcıda yoktur, WebCrypto'da hiç yoktur; dolayısıyla
   * `pkijs` tabanlı kütüphaneler bu dosyayı açamaz.
   */
  it.skipIf(!hasLegacyOpenssl)('eski RC2-40 kabını açar', () => {
    const { legacyRc2 } = keyMaterial()
    const bundle = loadPkcs12(legacyRc2.p12, legacyRc2.password)
    expect(bundle.privateKey.asymmetricKeyType).toBe('rsa')
    expect(new X509Certificate(Buffer.from(bundle.certificate)).subject).toContain(
      'Ornek Mali Muhur',
    )
  })

  it('EC anahtarlı kabı açar', () => {
    const { modernEc } = keyMaterial()
    const bundle = loadPkcs12(modernEc.p12, modernEc.password)
    expect(bundle.privateKey.asymmetricKeyType).toBe('ec')
  })

  it('parolasız kabı açar', () => {
    const { emptyPassword } = keyMaterial()
    expect(loadPkcs12(emptyPassword.p12, '').privateKey.asymmetricKeyType).toBe('rsa')
  })

  it('sertifika özel anahtarla eşleşir', () => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    expect(
      new X509Certificate(Buffer.from(bundle.certificate)).checkPrivateKey(bundle.privateKey),
    ).toBe(true)
  })

  it('zinciri uçtan köke doğru sıralar', () => {
    const { withChain } = keyMaterial()
    const bundle = loadPkcs12(withChain.p12, withChain.password)
    const leaf = new X509Certificate(Buffer.from(bundle.certificate))
    expect(bundle.chain.length).toBeGreaterThanOrEqual(1)

    // Her halka bir öncekini imzalamış olmalı.
    let current = leaf
    for (const der of bundle.chain) {
      const issuer = new X509Certificate(Buffer.from(der))
      expect(current.checkIssued(issuer)).toBe(true)
      current = issuer
    }
  })

  it('dostane adı okur', () => {
    const { modernRsa } = keyMaterial()
    expect(loadPkcs12(modernRsa.p12, modernRsa.password).friendlyName).toBe('Ornek Mali Muhur')
  })

  describe('hata durumları', () => {
    it('yanlış parola bütünlük hatası verir', () => {
      const { modernRsa } = keyMaterial()
      expect(() => loadPkcs12(modernRsa.p12, 'yanlış')).toThrow(Pkcs12Error)
      try {
        loadPkcs12(modernRsa.p12, 'yanlış')
      } catch (error) {
        // Bütünlük etiketi, içerik çözülmeden ÖNCE parolanın yanlış olduğunu
        // söyler; kullanıcıya "şifre yanlış" demenin doğru yeri burasıdır.
        expect((error as Pkcs12Error).reason).toBe('integrity')
      }
    })

    it('bütünlük denetimi kapatılınca yanlış parola içerikte yakalanır', () => {
      const { modernRsa } = keyMaterial()
      expect(() => loadPkcs12(modernRsa.p12, 'yanlış', { verifyMac: false })).toThrow(Pkcs12Error)
    })

    it('PKCS#12 olmayan girdi reddedilir', () => {
      expect(() => loadPkcs12(new Uint8Array([1, 2, 3]), '')).toThrow()
    })
  })
})

describe.skipIf(!canGenerateKeyMaterial())('uç sertifika seçimi', () => {
  /**
   * `localKeyId` özniteliği olmayan kaplar var; OpenSSL her zaman yazar ama
   * başka üreticiler yazmayabilir. O durumda seçim `checkPrivateKey`'e
   * düşer ve bu yol kapla değil doğrudan sınanmalı — aksi hâlde kodda durur
   * ama hiç çalıştırılmaz.
   */
  const candidates = (): {
    leaf: { der: Uint8Array; x509: X509Certificate; localKeyId?: string }
    other: { der: Uint8Array; x509: X509Certificate; localKeyId?: string }
    privateKey: ReturnType<typeof loadPkcs12>['privateKey']
  } => {
    const { modernRsa, modernEc } = keyMaterial()
    const own = loadPkcs12(modernRsa.p12, modernRsa.password)
    const foreign = loadPkcs12(modernEc.p12, modernEc.password)
    return {
      leaf: { der: own.certificate, x509: new X509Certificate(Buffer.from(own.certificate)) },
      other: {
        der: foreign.certificate,
        x509: new X509Certificate(Buffer.from(foreign.certificate)),
      },
      privateKey: own.privateKey,
    }
  }

  it('localKeyId yoksa açık anahtar karşılaştırmasıyla bulunur', () => {
    const { leaf, other, privateKey } = candidates()
    // Doğru sertifika listede İKİNCİ: "ilkini al" diyen bir uygulama yanılır.
    expect(selectLeafCertificate([other, leaf], undefined, privateKey)).toBe(leaf)
  })

  it('localKeyId varsa doğrudan onunla eşleşir', () => {
    const { leaf, other, privateKey } = candidates()
    const marked = { ...leaf, localKeyId: 'abc' }
    expect(selectLeafCertificate([other, marked], 'abc', privateKey)).toBe(marked)
  })

  it('localKeyId yanlış sertifikayı gösteriyorsa hata verir', () => {
    const { leaf, other, privateKey } = candidates()
    const misMarked = { ...other, localKeyId: 'abc' }
    expect(() => selectLeafCertificate([misMarked, leaf], 'abc', privateKey)).toThrow(
      /özel anahtarla eşleşmiyor/,
    )
  })

  it('hiçbiri eşleşmiyorsa hata verir', () => {
    const { other, privateKey } = candidates()
    expect(() => selectLeafCertificate([other], undefined, privateKey)).toThrow(/bulunamadı/)
  })
})
