import { createHash } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { toHex, utf8 } from '../src/core/bytes.js'
import { DerParseError } from '../src/core/errors.js'
import { parseCmsSignedData, verifyCmsSigner } from '../src/pki/cms.js'
import {
  buildTimestampRequest,
  parseTimestampResponse,
  parseTstInfo,
  verifyTimestampToken,
} from '../src/pki/tsp.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * RFC 3161 zaman damgası — çift yönlü sınama.
 *
 * Testler çevrimdışı bir OpenSSL TSA'sı kullanıyor, ağ yok. İki yön birden
 * kanıtlanıyor:
 *
 * 1. **Bizim ürettiğimiz isteği OpenSSL kabul ediyor** — `openssl ts -reply`
 *    onu okuyup jeton üretebiliyorsa, `TimeStampReq` kodlamamız gerçekten
 *    RFC 3161'dir.
 * 2. **OpenSSL'in ürettiği jetonu biz doğrulayabiliyoruz** — CMS
 *    ayrıştırıcısı, imza doğrulaması ve `TSTInfo` çözümlemesi doğrudur.
 *
 * Tek yönlü bir test bunların hiçbirini göstermezdi: kendi isteğimizi kendi
 * ayrıştırıcımızla okumak yalnızca kendimizle tutarlı olduğumuzu söyler.
 */

const digest = (data: Uint8Array, algorithm = 'sha256'): Uint8Array =>
  new Uint8Array(createHash(algorithm).update(Buffer.from(data)).digest())

describe.skipIf(!canGenerateKeyMaterial())('zaman damgası', () => {
  const veri = utf8('imzalanacak baytlar')

  it('ürettiğimiz isteği TSA kabul ediyor ve jeton veriyor', () => {
    const { tsa } = keyMaterial()
    const istek = buildTimestampRequest({ messageImprint: digest(veri) })
    const yanit = tsa.issue(istek)
    const jeton = parseTimestampResponse(yanit)
    expect(jeton.length).toBeGreaterThan(0)
  })

  it('jeton doğrulanıyor ve damgaladığı veriyle bağlanıyor', () => {
    const { tsa } = keyMaterial()
    const jeton = parseTimestampResponse(
      tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
    )

    const sonuc = verifyTimestampToken(jeton, { data: veri })
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.info.policyOid).toBe(tsa.policyOid)
    expect(sonuc.info.hashAlgorithm).toBe('sha256')
    expect(toHex(sonuc.info.messageImprint)).toBe(toHex(digest(veri)))
    expect(sonuc.info.genTime.getTime()).toBeLessThanOrEqual(Date.now() + 60_000)
    expect(toHex(sonuc.certificate)).toBe(toHex(tsa.certificate))
  })

  it('başka bir veriyle doğrulama reddediliyor', () => {
    const { tsa } = keyMaterial()
    const jeton = parseTimestampResponse(
      tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
    )

    const sonuc = verifyTimestampToken(jeton, { data: utf8('başka baytlar') })
    expect(sonuc.valid).toBe(false)
    if (sonuc.valid) return
    expect(sonuc.reason).toContain('başka bir veriyi damgalamış')
  })

  /**
   * `data` verilmezse jeton kriptografik olarak doğrulanır ama NEYİ
   * damgaladığı bilinmez. Bu tehlikeli bir kullanım; testin amacı davranışı
   * sabitlemek, önermek değil.
   */
  it('veri verilmezse özet bağı hiç kurulmuyor', () => {
    const { tsa } = keyMaterial()
    const jeton = parseTimestampResponse(
      tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
    )
    expect(verifyTimestampToken(jeton).valid).toBe(true)
  })

  it('SHA-384 ve SHA-512 ile de çalışıyor', () => {
    const { tsa } = keyMaterial()
    for (const algoritma of ['sha384', 'sha512'] as const) {
      const jeton = parseTimestampResponse(
        tsa.issue(
          buildTimestampRequest({
            messageImprint: digest(veri, algoritma),
            hashAlgorithm: algoritma,
          }),
        ),
      )
      const sonuc = verifyTimestampToken(jeton, { data: veri })
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.info.hashAlgorithm).toBe(algoritma)
    }
  })

  it("istenen politika OID'i jetona yansıyor", () => {
    const { tsa } = keyMaterial()
    const jeton = parseTimestampResponse(
      tsa.issue(buildTimestampRequest({ messageImprint: digest(veri), policyOid: tsa.policyOid })),
    )
    const sonuc = verifyTimestampToken(jeton, { data: veri })
    expect(sonuc.valid).toBe(true)
    if (!sonuc.valid) return
    expect(sonuc.info.policyOid).toBe(tsa.policyOid)
  })

  describe('tek kullanımlık sayı', () => {
    /**
     * Nonce, yanıtın tekrar oynatılmasına karşı tek koruma. Gönderilip de
     * denetlenmezse hiçbir işe yaramaz — bu yüzden denetim
     * `verifyTimestampToken` içinde.
     */
    it('istekte gönderilen değer jetonda geri geliyor', () => {
      const { tsa } = keyMaterial()
      const nonce = 0x0123456789abcdefn
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri), nonce })),
      )
      const sonuc = verifyTimestampToken(jeton, { data: veri, nonce })
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.info.nonce).toBe(nonce)
    })

    it('farklı bir değerle doğrulama reddediliyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri), nonce: 1n })),
      )
      const sonuc = verifyTimestampToken(jeton, { data: veri, nonce: 2n })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('aynı değil')
    })

    it('jetonda hiç yoksa tekrar oynatma şüphesi bildiriliyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      const sonuc = verifyTimestampToken(jeton, { data: veri, nonce: 5n })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('tekrar oynatılmış')
    })
  })

  describe('sertifika gömme', () => {
    it('varsayılan olarak TSA sertifikası jetona giriyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      expect(parseCmsSignedData(jeton).certificates.length).toBeGreaterThan(0)
    })

    /**
     * Sertifika gömülmezse jeton kendi başına doğrulanamaz. Arşivlenecek bir
     * imzada bu neredeyse her zaman istenmeyen durum — davranış burada
     * açıkça sabitleniyor ki kazara değişmesin.
     */
    it('istenmezse gömülmüyor ve jeton tek başına doğrulanamıyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(
          buildTimestampRequest({ messageImprint: digest(veri), requestCertificate: false }),
        ),
      )
      expect(parseCmsSignedData(jeton).certificates).toHaveLength(0)

      const sonuc = verifyTimestampToken(jeton, { data: veri })
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('sertifikası CMS içinde bulunamadı')
    })
  })

  describe('bozuk girdi', () => {
    it('özet uzunluğu algoritmayla tutmuyorsa reddediliyor', () => {
      expect(() => buildTimestampRequest({ messageImprint: new Uint8Array(16) })).toThrow(
        /32 bayt olmalı/,
      )
      expect(() =>
        buildTimestampRequest({ messageImprint: new Uint8Array(32), hashAlgorithm: 'sha512' }),
      ).toThrow(/64 bayt olmalı/)
    })

    it('CMS olmayan jeton açık hata veriyor', () => {
      const sonuc = verifyTimestampToken(utf8('bu bir jeton değil'))
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('CMS olarak okunamadı')
    })

    it('TSTInfo olmayan CMS reddediliyor', () => {
      // İmzalı ama içeriği TSTInfo olmayan bir CMS: kendi jetonumuzu alıp
      // içerik türünü değiştirmek yerine, bir sertifikayı CMS sanmak yeterli.
      const { modernRsa } = keyMaterial()
      const sonuc = verifyTimestampToken(modernRsa.p12)
      expect(sonuc.valid).toBe(false)
    })

    it('bozuk TSTInfo çözümlenemiyor', () => {
      expect(() => parseTstInfo(utf8('x'))).toThrow(DerParseError)
    })
  })

  describe('CMS katmanı', () => {
    it('jetonun imzacısı doğrudan da doğrulanabiliyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      const cms = parseCmsSignedData(jeton)
      const imzaci = cms.signerInfos[0]
      expect(imzaci).toBeDefined()
      if (imzaci === undefined) return

      expect(cms.contentType).toBe('1.2.840.113549.1.9.16.1.4')
      expect(imzaci.signedAttributes).toBeDefined()
      expect(verifyCmsSigner(cms, imzaci).valid).toBe(true)
    })

    /**
     * `messageDigest` denetimi olmadan saldırgan, CMS imzasını BOZMADAN
     * jetonun içeriğini değiştirebilir.
     *
     * Sebep şu: imza `signedAttrs` üzerinde hesaplanır, `eContent` üzerinde
     * değil. `eContent`i değiştirmek imzayı düşürmez — içeriği imzaya
     * bağlayan tek şey, `signedAttrs` içindeki `messageDigest`
     * özniteliğidir. Zaman damgasında bunun anlamı ağır: damganın
     * bildirdiği ZAMAN değiştirilebilir ve imza yine tutar.
     *
     * Test bunu birebir kuruyor: jetonun `TSTInfo` içeriğinde tek bir bayt
     * değiştiriliyor (uzunluk aynı kaldığı için dış yapı bozulmuyor).
     */
    it('içerik değiştirilirse messageDigest denetimi yakalıyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      const cms = parseCmsSignedData(jeton)
      const imzaci = cms.signerInfos[0]
      expect(imzaci).toBeDefined()
      expect(cms.content).toBeDefined()
      if (imzaci === undefined || cms.content === undefined) return

      // Sağlam hâli geçmeli.
      expect(verifyCmsSigner(cms, imzaci).valid).toBe(true)

      // İçerikte tek bayt değiştir — uzunluk sabit, imza dokunulmamış.
      const bozukIcerik = new Uint8Array(cms.content)
      const son = bozukIcerik.length - 1
      bozukIcerik[son] = ((bozukIcerik[son] ?? 0) ^ 0x01) & 0xff
      expect(toHex(bozukIcerik)).not.toBe(toHex(cms.content))

      const sonuc = verifyCmsSigner({ ...cms, content: bozukIcerik }, imzaci)
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('messageDigest içerikle eşleşmiyor')
    })

    it('messageDigest özniteliği hiç yoksa reddediliyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      const cms = parseCmsSignedData(jeton)
      const imzaci = cms.signerInfos[0]
      if (imzaci === undefined) return

      // İmzalanmış öznitelikleri koru ama messageDigest'i bulunamaz kıl.
      const kirpik = { ...imzaci, signedAttributes: [] }
      const sonuc = verifyCmsSigner(cms, kirpik)
      expect(sonuc.valid).toBe(false)
      if (sonuc.valid) return
      expect(sonuc.reason).toContain('messageDigest imzalanmış özniteliği yok')
    })

    /**
     * RFC 5652 §5.4: imza, `signedAttrs`ın DER kodlaması üzerinde
     * hesaplanır ve dış etiket `[0] IMPLICIT` değil `SET`tir. Kodlamayı
     * bozmak imzayı düşürmeli — bu, `PKI.js#402` ile aynı aile.
     */
    it('signedAttrs kodlaması bozulursa imza düşüyor', () => {
      const { tsa } = keyMaterial()
      const jeton = parseTimestampResponse(
        tsa.issue(buildTimestampRequest({ messageImprint: digest(veri) })),
      )
      const cms = parseCmsSignedData(jeton)
      const imzaci = cms.signerInfos[0]
      expect(imzaci?.signedAttributesDer).toBeDefined()
      if (imzaci?.signedAttributesDer === undefined) return

      // İlk bayt SET (0x31) olmalı; kaynaktaki [0] IMPLICIT (0xa0) DEĞİL.
      expect(imzaci.signedAttributesDer[0]).toBe(0x31)

      const bozuk = { ...imzaci, signedAttributesDer: new Uint8Array(imzaci.signedAttributesDer) }
      bozuk.signedAttributesDer[0] = 0xa0
      expect(verifyCmsSigner(cms, bozuk).valid).toBe(false)
    })
  })
})
