import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { DOMParser } from '@xmldom/xmldom'
import { afterAll, describe, expect, it } from 'vitest'
import * as XAdES from 'xadesjs'

import { loadPkcs12 } from '../src/pki/pkcs12.js'
import { sign } from '../src/sign.js'
import { verify } from '../src/verify.js'

import { canGenerateKeyMaterial, keyMaterial } from './key-material.js'

/**
 * `xadesjs` ile birlikte çalışabilirlik.
 *
 * `xadesjs` JavaScript ekosistemindeki en yaygın XAdES uygulamasıdır
 * (haftada ~22 bin indirme). Ürettiğimiz imzayı onun da kabul etmesi,
 * "kendi doğrulayıcımızla çalışıyor" ifadesinden çok daha güçlü bir
 * ifadedir.
 *
 * Sürüm 2.6.8'e sabitlendi. Davranış değişirse bu testler kırmızıya döner
 * ve bulgular yeniden değerlendirilir — sessizce eskimezler.
 */

XAdES.Application.setEngine('node', globalThis.crypto)

const directory = mkdtempSync(join(tmpdir(), 'e-imza-interop-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

/** `xadesjs` ile doğrular. */
const verifyWithXadesjs = async (xml: string): Promise<boolean> => {
  const document = new DOMParser().parseFromString(xml, 'application/xml')
  const signatures = document.getElementsByTagNameNS(
    'http://www.w3.org/2000/09/xmldsig#',
    'Signature',
  )
  const first = signatures[0]
  if (first === undefined) return false
  const signed = new XAdES.SignedXml(document)
  signed.LoadXml(first)
  return signed.Verify()
}

/** libxml2 ile kanonikleştirip özet alır — bağımsız hakem. */
const libxmlDigest = (xml: string, mode: '--c14n' | '--exc-c14n'): string => {
  const file = join(directory, `case-${String(Math.random()).slice(2)}.xml`)
  writeFileSync(file, xml, 'utf8')
  return createHash('sha256')
    .update(execFileSync('xmllint', [mode, file]))
    .digest('base64')
}

/** İmzalı belgeden `ds:Signature` öğesini metin olarak çıkarır. */
const withoutSignature = (signed: string): string => {
  const start = signed.indexOf('<ds:Signature')
  const end = signed.indexOf('</ds:Signature>') + '</ds:Signature>'.length
  return signed.slice(0, start) + signed.slice(end)
}

/** İmzadaki `URI=""` referansının beyan ettiği özet. */
const declaredDocumentDigest = (signed: string): string =>
  /<ds:Reference[^>]*URI=""[\s\S]*?<ds:DigestValue>([^<]+)<\/ds:DigestValue>/.exec(signed)?.[1] ??
  ''

const UBL_INVOICE = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension></ext:UBLExtensions>
  <cbc:ID>ABC2026000000001</cbc:ID>
  <cbc:Note>Ç &amp; Ş &lt; Ğ</cbc:Note>
</Invoice>`

describe.skipIf(!canGenerateKeyMaterial())('xadesjs ile birlikte çalışabilirlik', () => {
  const signWithOurs = (xml: string, placement: 'enveloped' | 'ubl-extension'): string => {
    const { modernRsa } = keyMaterial()
    const bundle = loadPkcs12(modernRsa.p12, modernRsa.password)
    return sign({
      xml,
      signer: { certificate: bundle.certificate, chain: bundle.chain },
      privateKey: bundle.privateKey,
      placement,
    })
  }

  it('kök altına atılan imzamızı xadesjs doğruluyor', async () => {
    const signed = signWithOurs('<Belge><Icerik>değer</Icerik></Belge>', 'enveloped')
    expect(verify(signed).valid).toBe(true)
    await expect(verifyWithXadesjs(signed)).resolves.toBe(true)
  })

  /**
   * `xadesjs#73` — 2018'de açıldı, hâlâ açık, 2.6.8'de yeniden üretiliyor.
   *
   * İmza `ext:ExtensionContent` içine gömüldüğünde xadesjs'in
   * `enveloped-signature` dönüşümü hiçbir şey yapmıyor. Bu iddia iki
   * ölçümle sabitleniyor:
   *
   * 1. libxml2, imza çıkarıldıktan sonra kalan belgeyi kanonikleştiriyor ve
   *    imzada beyan ettiğimiz özeti veriyor — yani bizim hesabımız doğru.
   * 2. xadesjs'in hesapladığı özet, imzanın HİÇ çıkarılmadığı belgenin
   *    özetiyle bire bir aynı — yani dönüşümü uygulamamış.
   *
   * Sonucu ağır: UBL uzantısına konmuş hiçbir e-Fatura imzası xadesjs ile
   * doğrulanamaz. Dönüşüm yalnızca imza kök öğenin doğrudan çocuğuyken
   * çalışıyor; bir önceki test onu gösteriyor.
   */
  it('UBL uzantısına gömülü imzada libxml2 bizi doğruluyor, xadesjs yanılıyor', async () => {
    const signed = signWithOurs(UBL_INVOICE, 'ubl-extension')
    expect(verify(signed).valid).toBe(true)

    // (1) Hakem: imza çıkarıldıktan sonra kalanın kanonik özeti, imzada
    //     beyan edilen özete eşit.
    expect(libxmlDigest(withoutSignature(signed), '--exc-c14n')).toBe(
      declaredDocumentDigest(signed),
    )

    // (2) xadesjs reddediyor ve hangi özeti hesapladığını söylüyor.
    let rejected = false
    let reported = ''
    try {
      await verifyWithXadesjs(signed)
    } catch (error) {
      rejected = true
      // xml-core'un `XmlError`'ı `Error`'dan TÜREMİYOR: `String(error)`
      // "[object Object]" veriyor ve `instanceof Error` tutmuyor. Mesaj
      // yine de kendi alanında duruyor.
      const message = String((error as { message?: unknown }).message ?? error)
      reported = /Calculated digest is ([A-Za-z0-9+/=]+)/.exec(message)?.[1] ?? ''
    }
    expect(rejected).toBe(true)

    // Hesapladığı şey, imzanın çıkarılmadığı belgenin özeti.
    expect(reported).not.toBe('')
    expect(reported).toBe(libxmlDigest(signed, '--exc-c14n'))
    expect(reported).not.toBe(declaredDocumentDigest(signed))
  })
})
