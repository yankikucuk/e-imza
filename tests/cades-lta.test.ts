import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import {
  archiveTimestampInput,
  buildAtsHashIndex,
  parseAtsHashIndex,
  readArchiveComponents,
} from '../src/cades/archive.js'
import { UnsignedAttribute } from '../src/cades/constants.js'
import { addUnsignedAttributes } from '../src/cades/edit.js'
import { cadesSign } from '../src/cades/sign.js'
import { cadesArchiveTimestamp, cadesTimestampRequest, cadesUpgrade } from '../src/cades/upgrade.js'
import { cadesVerify } from '../src/cades/verify.js'
import { concat, toHex } from '../src/core/bytes.js'
import { SigningError } from '../src/core/errors.js'
import { cmsAttribute } from '../src/pki/cms-build.js'
import { attributeValues, parseCmsSignedData } from '../src/pki/cms.js'
import { buildOcspRequest } from '../src/pki/ocsp.js'
import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { parseTimestampResponse } from '../src/pki/tsp.js'

const ARCHIVE_TIMESTAMP_V3_OID = UnsignedAttribute.ARCHIVE_TIMESTAMP_V3

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * CAdES-LTA — `archive-time-stamp-v3`.
 *
 * Kaynak: **ETSI TS 101 733 V2.2.1 §6.4.2 ve §6.4.3.**
 *
 * Bu dosyanın tasarımı, bu depoda tekrar eden tuzağın etrafında kuruldu:
 * *üretici ile doğrulayıcı aynı bizsek, ikisi aynı yanlışı yaparsa testler
 * geçer.* Arşiv damgasında bu risk en yüksek seviyede, çünkü girdiyi
 * doğrulayan bağımsız bir uygulama elimizde yok. Bu yüzden üç ayrı
 * bağımsızlık kaynağı kullanılıyor:
 *
 * 1. **`openssl ts -verify -token_in`** — jetonun imzasının bozulmadığını
 *    ve `messageImprint`in bizim ürettiğimiz girdi baytlarının özeti
 *    olduğunu OpenSSL doğruluyor.
 * 2. **`openssl asn1parse`** — `SignerInfo` alanlarının ham dilimlerini ve
 *    `ATSHashIndex`in kodlamasını OpenSSL'in gördüğü hâlle karşılaştırıyor.
 * 3. **`openssl dgst`** — indeksteki her özeti bağımsız hesaplatıyor.
 *
 * Kalan boşluk dürüstçe şu: bileşenlerin **sırası** standardın metninden
 * alındı ve bir ETSI uygulamasıyla karşılaştırılamadı. Sıra, §6.4.3'ün
 * dört maddeli listesi olarak testte ayrıca yazılı.
 */

const directory = mkdtempSync(join(tmpdir(), 'e-imza-lta-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

const OPENSSL =
  ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find((p) => {
    try {
      execFileSync(p, ['version'], { stdio: 'ignore' })
      return true
    } catch {
      return false
    }
  }) ?? 'openssl'

let counter = 0
/** Baytları geçici bir dosyaya yazar ve yolunu verir. */
const dosya = (bytes: Uint8Array, ext = 'bin'): string => {
  counter += 1
  const path = join(directory, `v${String(counter)}.${ext}`)
  writeFileSync(path, bytes)
  return path
}

/** `openssl` çalıştırır; hata çıktısı da dönerin içinde. */
const openssl = (args: readonly string[]): string => {
  try {
    return execFileSync(OPENSSL, [...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (error) {
    const e = error as { stdout?: Buffer; stderr?: Buffer }
    return (e.stdout?.toString() ?? '') + (e.stderr?.toString() ?? '')
  }
}

const VERI = new TextEncoder().encode('Arşivlenecek belge — 2026.')

describe.skipIf(!canGenerateKeyMaterial())('CAdES-LTA', () => {
  /** T ve LT seviyelerinden geçmiş, arşivlenmeye hazır bir imza. */
  const uzunDonem = (): Uint8Array => {
    const material = keyMaterial()
    const bundle = loadPkcs12(material.withChain.p12, material.withChain.password)
    const cms = cadesSign({
      data: VERI,
      signer: { certificate: bundle.certificate, chain: bundle.chain },
      privateKey: bundle.privateKey,
      attached: true,
    })
    const token = parseTimestampResponse(material.tsa.issue(cadesTimestampRequest({ cms })))
    const withT = cadesUpgrade({ cms, to: 'T', token })
    const ocsp = material.ocsp.respond(
      buildOcspRequest({
        certificate: bundle.certificate,
        issuer: material.intermediateCertificate,
      }),
    )
    return cadesUpgrade({
      cms: withT,
      to: 'LT',
      certificates: [material.intermediateCertificate, material.rootCertificate],
      ocspResponses: [ocsp],
    })
  }

  /** Arşiv damgası atılmış imza. */
  const arsiv = (cms = uzunDonem()): Uint8Array => {
    const { tsa } = keyMaterial()
    const pending = cadesArchiveTimestamp({ cms })
    return pending.finish(parseTimestampResponse(tsa.issue(pending.request)))
  }

  describe('§6.4.3 — girdinin bileşimi', () => {
    /**
     * §6.4.3, madde 3: girdiye `version`, `sid`, `digestAlgorithm`,
     * `signedAttrs`, `signatureAlgorithm`, `signature` alanları girer —
     * **`unsignedAttrs` GİRMEZ**. Girseydi, damganın kendisi eklendiği
     * anda girdi değişir ve damga kendi kendini geçersiz kılardı.
     */
    it('SignerInfo alanları unsignedAttrs HARİÇ alınıyor', () => {
      const cms = uzunDonem()
      const components = readArchiveComponents(cms)
      expect(components.signerFields).toHaveLength(6)

      // OpenSSL'in gördüğü SignerInfo alanları ile karşılaştır: dökümdeki
      // ilk alan `version` (INTEGER 1), sonuncusu `signature` (OCTET
      // STRING). unsignedAttrs bir [1] cont ve listede olmamalı.
      const dokum = openssl(['asn1parse', '-inform', 'DER', '-in', dosya(cms, 'der'), '-i'])
      expect(dokum).toContain('cont [ 1 ]') // yapıda VAR
      const etiketler = components.signerFields.map((f) => f[0])
      // [1] IMPLICIT etiketi 0xa1; alınan alanların hiçbiri o olmamalı.
      expect(etiketler).not.toContain(0xa1)
      // İlk alan INTEGER (0x02), dördüncüsü [0] IMPLICIT signedAttrs (0xa0).
      expect(etiketler[0]).toBe(0x02)
      expect(etiketler[3]).toBe(0xa0)
    })

    /**
     * §6.4.3, madde 2: "The octets representing the **hash** of the signed
     * data." Verinin kendisi değil, özeti giriyor — ve özet, arşiv
     * damgasının algoritmasıyla alınıyor.
     */
    it('ikinci bileşen içeriğin KENDİSİ değil ÖZETİ', () => {
      const cms = uzunDonem()
      const components = readArchiveComponents(cms)
      const index = buildAtsHashIndex(components, 'sha256')
      const girdi = archiveTimestampInput(components, index, 'sha256')

      const ozet = new Uint8Array(createHash('sha256').update(VERI).digest())
      expect(toHex(girdi)).toContain(toHex(ozet))
      // Ham veri girdide GEÇMEMELİ.
      expect(toHex(girdi)).not.toContain(toHex(VERI))
    })

    /**
     * §6.4.3'ün dört maddesi, birleştirme sırasıyla. Beklenen değer burada
     * ELLE kuruluyor; `archiveTimestampInput`in kendisi çağrılmıyor ki iki
     * taraf aynı yanlışı yapamasın.
     */
    it('girdi = eContentType ‖ H(içerik) ‖ SignerInfo alanları ‖ ATSHashIndex', () => {
      const cms = uzunDonem()
      const components = readArchiveComponents(cms)
      const index = buildAtsHashIndex(components, 'sha256')

      const elle = concat(
        components.eContentTypeDer,
        new Uint8Array(createHash('sha256').update(VERI).digest()),
        ...components.signerFields,
        index,
      )
      expect(toHex(archiveTimestampInput(components, index, 'sha256'))).toBe(toHex(elle))
    })

    it('ayrık imzada içerik verilmezse açık hata veriyor', () => {
      const material = keyMaterial()
      const bundle = loadPkcs12(material.modernRsa.p12, material.modernRsa.password)
      const ayrik = cadesSign({
        data: VERI,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
        attached: false,
      })
      const components = readArchiveComponents(ayrik)
      expect(() => archiveTimestampInput(components, new Uint8Array([0x30, 0x00]))).toThrow(
        SigningError,
      )
    })
  })

  describe('§6.4.2 — ATSHashIndex', () => {
    it('SHA-256 varsayılan olduğu için hashIndAlgorithm YAZILMIYOR', () => {
      const index = buildAtsHashIndex(readArchiveComponents(uzunDonem()), 'sha256')
      const dokum = openssl(['asn1parse', '-inform', 'DER', '-in', dosya(index, 'der'), '-i'])
      // Üç SEQUENCE (indeksler) + dış SEQUENCE; algoritma OID'i yok.
      expect(dokum).not.toContain('sha256')
      expect(dokum).not.toContain('OBJECT')
    })

    it('SHA-384 seçilirse hashIndAlgorithm YAZILIYOR', () => {
      const index = buildAtsHashIndex(readArchiveComponents(uzunDonem()), 'sha384')
      const dokum = openssl(['asn1parse', '-inform', 'DER', '-in', dosya(index, 'der'), '-i'])
      expect(dokum).toContain('sha384')
      expect(parseAtsHashIndex(index).hashAlgorithmOid).toBe('2.16.840.1.101.3.4.2.2')
    })

    /**
     * §6.4.2: "Each hash shall be the result … of a hash computation on the
     * **entire encoded component including its tag, length and value
     * octets**." Özetleri OpenSSL hesaplıyor.
     */
    it('her indeks kaydı, bileşenin tam DER’inin SHA-256’sı — OpenSSL ile', () => {
      const components = readArchiveComponents(uzunDonem())
      const index = parseAtsHashIndex(buildAtsHashIndex(components, 'sha256'))

      const opensslSha256 = (bytes: Uint8Array): string => {
        const cikti = openssl(['dgst', '-sha256', '-r', dosya(bytes, 'der')])
        return (cikti.split(' ')[0] ?? '').toLowerCase()
      }

      expect(index.certificatesHashIndex.map((h) => toHex(h))).toEqual(
        components.certificateInstances.map(opensslSha256),
      )
      expect(index.unsignedAttrsHashIndex.map((h) => toHex(h))).toEqual(
        components.unsignedAttributeInstances.map(opensslSha256),
      )
    })

    /**
     * §6.4.2: "A hash value for **every** instance … shall be included …
     * **No other** hash value shall be included."
     *
     * Sayılar BAĞIMSIZ kaynaklardan alınıyor. `readArchiveComponents`in
     * kendi çıktısına saymak hiçbir şey kanıtlamaz: o fonksiyon bir
     * bileşeni atlarsa hem indeks hem beklenti birlikte küçülür ve test
     * geçer. Mutasyonla ölçüldü — sertifika listesinin ilk üyesini düşüren
     * bir hata tam olarak böyle kaçmıştı.
     */
    it('sertifika sayısı OpenSSL ile, öznitelik sayısı ayrı ayrıştırıcıyla doğrulanıyor', () => {
      const cms = uzunDonem()
      const components = readArchiveComponents(cms)
      const index = parseAtsHashIndex(buildAtsHashIndex(components, 'sha256'))

      // Bağımsız tanık 1: OpenSSL sertifikaları kendi sayıyor.
      const cikti = openssl([
        'pkcs7',
        '-inform',
        'DER',
        '-in',
        dosya(cms, 'der'),
        '-print_certs',
        '-noout',
      ])
      const opensslSayisi = (cikti.match(/^subject=/gm) ?? []).length
      expect(opensslSayisi).toBe(3) // uç + ara + kök
      expect(index.certificatesHashIndex).toHaveLength(opensslSayisi)

      // Bağımsız tanık 2: genel CMS ayrıştırıcısı — arşiv yolundan ayrı kod.
      const signer = parseCmsSignedData(cms).signerInfos[0]
      expect(index.unsignedAttrsHashIndex).toHaveLength(signer?.unsignedAttributes?.length ?? 0)
      // T + LT sonrası: signature-timestamp, certificate-values,
      // revocation-values.
      expect(index.unsignedAttrsHashIndex).toHaveLength(3)
      // Ayrık imza olmadığı için CRL indeksi boş.
      expect(index.crlsHashIndex).toHaveLength(0)
    })
  })

  describe('OpenSSL, arşiv damgasını bağımsız doğruluyor', () => {
    /**
     * En değerli test. `openssl ts -verify -token_in`, jetonun imzasını ve
     * `messageImprint`in verilen verinin özeti olduğunu KENDİ hesaplıyor.
     * `ats-hash-index`i jetona ekledikten sonra da geçmesi, imzalanmamış
     * alana yazmanın jetonu bozmadığını gösteriyor.
     */
    it('ts -verify -token_in girdimizi kabul ediyor', () => {
      const material = keyMaterial()
      const pending = cadesArchiveTimestamp({ cms: uzunDonem() })
      const jeton = parseTimestampResponse(material.tsa.issue(pending.request))
      const lta = pending.finish(jeton)

      // İmzaya yerleşmiş, `ats-hash-index` eklenmiş jetonu geri çıkar.
      const gomulu = arsivJetonu(lta)
      const kokPem = join(directory, 'kok.pem')
      execFileSync(OPENSSL, [
        'x509',
        '-inform',
        'DER',
        '-in',
        dosya(material.tsa.rootCertificate, 'der'),
        '-out',
        kokPem,
      ])

      const cikti = openssl([
        'ts',
        '-verify',
        '-token_in',
        '-in',
        dosya(gomulu, 'der'),
        '-data',
        dosya(pending.stampedBytes),
        '-CAfile',
        kokPem,
      ])
      expect(cikti).toContain('Verification: OK')
    })

    it('başka veriyle çağrılırsa OpenSSL de reddediyor', () => {
      const material = keyMaterial()
      const pending = cadesArchiveTimestamp({ cms: uzunDonem() })
      const jeton = parseTimestampResponse(material.tsa.issue(pending.request))
      const gomulu = arsivJetonu(pending.finish(jeton))

      const kokPem = join(directory, 'kok2.pem')
      execFileSync(OPENSSL, [
        'x509',
        '-inform',
        'DER',
        '-in',
        dosya(material.tsa.rootCertificate, 'der'),
        '-out',
        kokPem,
      ])
      const cikti = openssl([
        'ts',
        '-verify',
        '-token_in',
        '-in',
        dosya(gomulu, 'der'),
        '-data',
        dosya(new Uint8Array([1, 2, 3])),
        '-CAfile',
        kokPem,
      ])
      expect(cikti).not.toContain('Verification: OK')
    })

    /**
     * İndeks, jetonun `unsignedAttrs`ında olmalı — `signedAttrs`ında değil.
     * Orada olsaydı jetonun imzası onu kapsardı ve TSA'nın imzalamadığı bir
     * şeyi imzalamış gibi görünürdü.
     *
     * OID iki biçimde de kabul ediliyor: yeni OpenSSL sürümleri bu OID'i
     * TANIYOR ve `id-aa-ATSHashIndex` diye yazıyor, eskileri ham rakamları
     * basıyor. Ubuntu'daki 3.0 ile macOS'taki 3.6 arasındaki bu fark canlı
     * olarak CI'da yaşandı; ikisini de kabul etmek doğrulamayı zayıflatmıyor
     * çünkü aranan şey OID'in kendisi.
     */
    it('ats-hash-index jetonun imzalanmamış özniteliklerinde', () => {
      const gomulu = arsivJetonu(arsiv())
      const dokum = openssl(['asn1parse', '-inform', 'DER', '-in', dosya(gomulu, 'der'), '-i'])
      const at = Math.max(dokum.indexOf('id-aa-ATSHashIndex'), dokum.indexOf('0.4.0.1733.2.5'))
      expect(at).toBeGreaterThan(-1)
      // `cont [ 1 ]` = unsignedAttrs; indeks ondan SONRA gelmeli.
      expect(dokum.slice(0, at)).toContain('cont [ 1 ]')
    })
  })

  describe('uçtan uca', () => {
    it('seviye LTA oluyor ve damga her bileşeni kapsıyor', () => {
      const sonuc = cadesVerify(arsiv())
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).toBe('LTA')
      const damga = sonuc.timestamps.find((t) => t.kind === 'archive')
      expect(damga?.valid).toBe(true)
      expect(damga?.coversAllComponents).toBe(true)
      expect(damga?.genTime).toBeInstanceOf(Date)
    })

    it('LT olmadan arşiv damgası atılırsa seviye LTA olmuyor', () => {
      const material = keyMaterial()
      const bundle = loadPkcs12(material.modernRsa.p12, material.modernRsa.password)
      const cms = cadesSign({
        data: VERI,
        signer: { certificate: bundle.certificate },
        privateKey: bundle.privateKey,
        attached: true,
      })
      const sonuc = cadesVerify(arsiv(cms))
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      expect(sonuc.level).not.toBe('LTA')
    })

    it('arşiv damgasından sonra sertifika eklenirse kapsam eksik raporlanıyor', () => {
      const material = keyMaterial()
      const lta = arsiv()
      const sonra = cadesUpgrade({
        cms: lta,
        to: 'LT',
        certificates: [material.tsa.certificate],
        ocspResponses: [
          material.ocsp.respond(
            buildOcspRequest({
              certificate: loadPkcs12(material.withChain.p12, material.withChain.password)
                .certificate,
              issuer: material.intermediateCertificate,
            }),
          ),
        ],
      })
      const sonuc = cadesVerify(sonra)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      const damga = sonuc.timestamps.find((t) => t.kind === 'archive')
      expect(damga?.valid).toBe(true)
      expect(damga?.coversAllComponents).toBe(false)
      expect(sonuc.warnings.map((w) => w.code)).toContain('archive-timestamp-partial-coverage')
    })

    it('ikinci arşiv damgası atılabiliyor, ikisi de tutuyor', () => {
      const ikinci = arsiv(arsiv())
      const sonuc = cadesVerify(ikinci)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      const damgalar = sonuc.timestamps.filter((t) => t.kind === 'archive')
      expect(damgalar).toHaveLength(2)
      expect(damgalar.every((d) => d.valid)).toBe(true)
      expect(damgalar.every((d) => d.coversAllComponents === true)).toBe(true)
      expect(sonuc.level).toBe('LTA')
    })

    /**
     * **En kritik test.** Doğrulama, jetonun kriptografik geçerliliğine
     * değil, `messageImprint`in YENİDEN KURULAN girdinin özeti olmasına
     * bakmak zorunda. Bakmazsa "arşiv damgası geçerli" demek, geçerli
     * herhangi bir jetonun bu imzaya yapıştırılabileceği anlamına gelir.
     *
     * Mutasyonla ölçüldü: doğrulamadaki veri bağını kaldıran bir hata, bu
     * test eklenmeden önce hiçbir testi düşürmüyordu.
     */
    it('geçerli ama BAŞKA bir girdiyi damgalayan jeton reddediliyor', () => {
      const material = keyMaterial()
      const baskasi = cadesArchiveTimestamp({ cms: uzunDonem() })
      const yabanciJeton = parseTimestampResponse(material.tsa.issue(baskasi.request))

      const bizimki = cadesArchiveTimestamp({ cms: uzunDonem() })
      // Denetimi kapatarak yanlış jetonu zorla yerleştir.
      const bozuk = bizimki.finish(yabanciJeton, { verifyToken: false })

      const sonuc = cadesVerify(bozuk)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      const damga = sonuc.timestamps.find((t) => t.kind === 'archive')
      // Jetonun kendisi kusursuz — imzası geçerli, TSA'sı doğru. Reddin
      // TEK sebebi neyi damgaladığının tutmaması.
      expect(damga?.valid).toBe(false)
      expect(sonuc.level).toBe('LT')
      expect(sonuc.warnings.map((w) => w.code)).toContain('timestamp-invalid')
    })

    /**
     * Girdinin ikinci bileşeni imzalanan verinin özeti. İçerik değişirse
     * arşiv damgası da düşmeli — yalnızca imza değil.
     */
    it('içerik değişirse arşiv damgası da düşüyor', () => {
      const material = keyMaterial()
      const bundle = loadPkcs12(material.withChain.p12, material.withChain.password)
      const ayrik = cadesSign({
        data: VERI,
        signer: { certificate: bundle.certificate, chain: bundle.chain },
        privateKey: bundle.privateKey,
        attached: false,
      })
      const token = parseTimestampResponse(
        material.tsa.issue(cadesTimestampRequest({ cms: ayrik })),
      )
      const withT = cadesUpgrade({ cms: ayrik, to: 'T', token })
      const lt = cadesUpgrade({
        cms: withT,
        to: 'LT',
        certificates: [material.intermediateCertificate],
        ocspResponses: [
          material.ocsp.respond(
            buildOcspRequest({
              certificate: bundle.certificate,
              issuer: material.intermediateCertificate,
            }),
          ),
        ],
      })
      const pending = cadesArchiveTimestamp({ cms: lt, content: VERI })
      const lta = pending.finish(parseTimestampResponse(material.tsa.issue(pending.request)))

      // Doğru içerikle: damga tutuyor.
      const dogru = cadesVerify(lta, { content: VERI })
      expect(dogru.valid).toBe(true)
      if (!dogru.valid) return
      expect(dogru.timestamps.find((t) => t.kind === 'archive')?.valid).toBe(true)

      // Değiştirilmiş içerikle: hem imza hem arşiv damgası düşüyor.
      const bozuk = cadesVerify(lta, { content: new TextEncoder().encode('Başka belge.') })
      expect(bozuk.valid).toBe(false)
    })

    it('başka bir imzanın jetonu reddediliyor', () => {
      const material = keyMaterial()
      const baskasi = cadesArchiveTimestamp({ cms: uzunDonem() })
      const jeton = parseTimestampResponse(material.tsa.issue(baskasi.request))

      const bizimki = cadesArchiveTimestamp({ cms: uzunDonem() })
      expect(() => bizimki.finish(jeton)).toThrow(SigningError)
    })

    /**
     * §6.4.3: "The archive-time-stamp-v3 **shall** include as an unsigned
     * attribute a single ats-hash-index." İndeks olmadan girdi yeniden
     * kurulamaz; damgayı "geçerli" saymak, neyi damgaladığını bilmeden
     * geçerli demek olurdu.
     */
    it('ats-hash-index olmadan gömülmüş arşiv damgası geçersiz sayılıyor', () => {
      const material = keyMaterial()
      const cms = uzunDonem()
      const pending = cadesArchiveTimestamp({ cms })
      const jeton = parseTimestampResponse(material.tsa.issue(pending.request))

      // Jetonu ATSv3 olarak, indeks EKLEMEDEN yerleştir.
      const indekssiz = addUnsignedAttributes(cms, [cmsAttribute(ARCHIVE_TIMESTAMP_V3_OID, jeton)])
      const sonuc = cadesVerify(indekssiz)
      expect(sonuc.valid).toBe(true)
      if (!sonuc.valid) return
      const damga = sonuc.timestamps.find((t) => t.kind === 'archive')
      expect(damga?.valid).toBe(false)
      expect(damga?.reason).toContain('ats-hash-index')
      expect(sonuc.level).toBe('LT')
    })
  })
})

/** İmzaya gömülü `archive-time-stamp-v3` jetonunu geri çıkarır. */
const arsivJetonu = (cms: Uint8Array): Uint8Array => {
  const signer = parseCmsSignedData(cms).signerInfos[0]
  if (signer === undefined) throw new Error('imzacı yok')
  const values = attributeValues(signer.unsignedAttributes, ARCHIVE_TIMESTAMP_V3_OID)
  const first = values[0]
  if (first === undefined) throw new Error('ATSv3 özniteliği bulunamadı')
  return first.raw
}
