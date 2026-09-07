import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { canonicalize } from '../src/c14n/canonicalize.js'
import { parseXml } from '../src/xml/parse.js'

/**
 * Bağımsız oracle testi: kendi kanonikleştiricimizin çıktısını **libxml2**
 * ile karşılaştırır.
 *
 * Kendi testlerimizi kendi anladığımız spesifikasyona göre yazarız; ikisi de
 * aynı yanlış anlamayı paylaşabilir. libxml2 bizden bağımsız, yirmi yıldır
 * kullanılan bir C uygulamasıdır — bir yorum farkı varsa burada çıkar.
 *
 * `xmllint` yoksa test atlanır; CI'da kurulu olduğu için orada gerçekten
 * koşar. Atlanması sessiz bir geçiş değil, açık bir atlamadır.
 */

const hasXmllint = ((): boolean => {
  try {
    execFileSync('xmllint', ['--version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

const directory = mkdtempSync(join(tmpdir(), 'e-imza-c14n-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

/** `xmllint`'in her iki kipi de yorumları çıktıya yazar. */
const reference = (xml: string, mode: '--c14n' | '--exc-c14n'): string => {
  const file = join(directory, `case-${String(Math.random()).slice(2)}.xml`)
  writeFileSync(file, xml, 'utf8')
  return execFileSync('xmllint', [mode, file], { encoding: 'utf8' })
}

const CASES: readonly { readonly name: string; readonly xml: string }[] = [
  {
    name: 'öznitelik ve ad alanı sıralaması',
    xml: '<doc>\n  <a x="1" b:y="2" a2="3" xmlns:b="urn:b" xmlns:a="urn:a" a:z="4"/>\n</doc>',
  },
  {
    name: 'iç içe varsayılan ad alanı ve iptali',
    xml: '<r xmlns="urn:r"><a xmlns=""><b xmlns="urn:b"><c xmlns=""/></b></a></r>',
  },
  {
    name: 'kökte ön ek (xmldsigjs#59 senaryosu)',
    xml: '<ns2:R xmlns="urn:d" xmlns:ns2="urn:two"><ns2:C><Leaf>x</Leaf></ns2:C></ns2:R>',
  },
  {
    name: 'karakter başvuruları ve kaçırma',
    xml: '<d><t>a&#xD;&#10;b</t><e q=\'x&#x9;y &amp; z&gt;"0"\'/><g>&lt;&amp;&gt;</g></d>',
  },
  {
    name: 'boşluk ve karışık içerik',
    xml: '<m>\n  A\n  <c>   </c>\n  B <i>iç</i> C\n</m>',
  },
  {
    name: 'yorum ve işlem yönergesi',
    xml: '<?target veri?>\n<d><!--yorum--><a/><?p2?></d>\n<!--son-->',
  },
  {
    name: 'xml:* öznitelikleri',
    xml: '<r xml:lang="tr" xml:space="preserve"><c xml:lang="en">x</c></r>',
  },
  {
    name: 'yinelenen ad alanı bildirimi bastırılır',
    xml: '<r xmlns:p="urn:p"><p:a xmlns:p="urn:p"><p:b/></p:a></r>',
  },
  {
    name: 'UBL-TR benzeri belge',
    xml: `<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent/></ext:UBLExtension></ext:UBLExtensions>
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:ProfileID>TEMELFATURA</cbc:ProfileID>
  <cac:AccountingSupplierParty><cac:Party><cac:PartyIdentification><cbc:ID schemeID="VKN">1234567890</cbc:ID></cac:PartyIdentification></cac:Party></cac:AccountingSupplierParty>
  <cbc:Note>Ç &amp; Ş &lt; Ğ</cbc:Note>
</Invoice>`,
  },
]

describe.skipIf(!hasXmllint)('libxml2 ile fark testi', () => {
  for (const testCase of CASES) {
    it(`kapsayıcı (c14n 1.0) — ${testCase.name}`, () => {
      expect(canonicalize(parseXml(testCase.xml), { algorithm: 'c14n10-with-comments' })).toBe(
        reference(testCase.xml, '--c14n'),
      )
    })

    it(`dışlayıcı (exc-c14n) — ${testCase.name}`, () => {
      expect(canonicalize(parseXml(testCase.xml), { algorithm: 'exc-c14n-with-comments' })).toBe(
        reference(testCase.xml, '--exc-c14n'),
      )
    })
  }
})

describe('oracle mevcudiyeti', () => {
  it('xmllint bulunmalı — yoksa fark testi sessizce atlanmış olur', () => {
    // Bu iddia, oracle'ın kaybolduğunu görünür kılmak içindir: fark testleri
    // atlandığında en azından TEK bir test kırmızı olur.
    expect(hasXmllint).toBe(true)
  })
})
