import { describe, expect, it } from 'vitest'

import { DoctypeNotAllowedError } from '../core/errors.js'
import { childNamed, walkElements, type XmlDocument } from '../xml/node.js'
import { parseXml } from '../xml/parse.js'

import { c14nAlgorithmFromUri, canonicalize, C14N_URI } from './canonicalize.js'

/**
 * Bu dosyanın çoğu, W3C'nin `REC-xml-c14n-20010315` belgesindeki **resmî
 * uygunluk örnekleridir** (§3.1–3.6). Beklenen çıktılar spesifikasyondan
 * birebir alınmıştır; yeniden hesaplanmamıştır.
 *
 * Neden önemli: incelenen JavaScript kütüphanelerinin hiçbirinde bu
 * vektörler yok. `xadesjs#12` ("merlin ve phaos testlerini regresyon
 * paketine ekle") 2016'dan beri açık ve kütüphane 2025'te bu test hiç
 * eklenmeden arşivlendi. Kanonikleştirmeyle ilgili beş ayrı issue
 * (`xmldsigjs#11`, `#59`, `#49`, `xml-crypto#238`, `#538`) bu boşluğun
 * doğrudan sonucu.
 *
 * §3.5 (varlık başvuruları) burada yok: DTD gerektirir, bu kütüphane ise
 * DTD'yi kasten reddeder — gerekçe {@link DoctypeNotAllowedError} içinde.
 */

const c14n = (xml: string, withComments = false): string =>
  canonicalize(parseXml(xml), {
    algorithm: withComments ? 'c14n10-with-comments' : 'c14n10',
  })

describe('W3C Canonical XML 1.0 uygunluk örnekleri', () => {
  it('§3.1 — belge öğesi dışındaki yönergeler ve yorumlar', () => {
    // Spesifikasyondaki girdiden yalnızca DOCTYPE satırı çıkarıldı; bu
    // kütüphane DTD kabul etmiyor. Kalan her şey birebir.
    const input = `<?xml version="1.0"?>

<?xml-stylesheet   href="doc.xsl"
   type="text/xsl"   ?>

<doc>Hello, world!<!-- Comment 1 --></doc>

<?pi-without-body ?>

<!-- Comment 2 -->`

    expect(c14n(input)).toBe(
      `<?xml-stylesheet href="doc.xsl"
   type="text/xsl"   ?>
<doc>Hello, world!</doc>
<?pi-without-body?>`,
    )

    expect(c14n(input, true)).toBe(
      `<?xml-stylesheet href="doc.xsl"
   type="text/xsl"   ?>
<doc>Hello, world!<!-- Comment 1 --></doc>
<?pi-without-body?>
<!-- Comment 2 -->`,
    )
  })

  it('§3.2 — belge içeriğindeki boşluk aynen korunur', () => {
    const input = `<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>`
    // Kanonik biçim girdiyle aynıdır: kanonikleştirme boşluk "temizlemez".
    // Temizleyen bir uygulama, imzalanan belgeyi değiştirmiş olur.
    expect(c14n(input)).toBe(input)
  })

  it('§3.3 — başlangıç/bitiş etiketleri, öznitelik ve ad alanı sıralaması', () => {
    const input = `<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>`

    expect(c14n(input)).toBe(`<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>`)
  })

  it('§3.4 — karakter değişiklikleri ve karakter başvuruları', () => {
    const input = `<doc>
   <text>First line&#x0d;&#10;Second line</text>
   <value>&#x32;</value>
   <compute>value&gt;"0" &amp;&amp; value&lt;"10" ?"valid":"error"</compute>
   <compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>
   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>
   <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
</doc>`

    expect(c14n(input)).toBe(`<doc>
   <text>First line&#xD;
Second line</text>
   <value>2</value>
   <compute>value&gt;"0" &amp;&amp; value&lt;"10" ?"valid":"error"</compute>
   <compute expr="value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;">valid</compute>
   <norm attr=" '    &#xD;&#xA;&#x9;   ' "></norm>
   <normNames attr="   A    &#xD;&#xA;&#x9;   B   "></normNames>
   <normId id=" '    &#xD;&#xA;&#x9;   ' "></normId>
</doc>`)
  })

  it('§3.6 — UTF-8 kodlaması', () => {
    expect(c14n('<doc>\n   <text>&#169;</text>\n</doc>')).toBe('<doc>\n   <text>©</text>\n</doc>')
  })

  it('§3.5 kapsam dışıdır — DTD reddedilir', () => {
    expect(() => parseXml('<!DOCTYPE doc []><doc/>')).toThrow(DoctypeNotAllowedError)
  })
})

describe('satır sonu normalizasyonu', () => {
  /**
   * `xml-crypto#238`'in tam senaryosu. Kaynaktaki DÜZ `\r\n`, XML 1.0
   * §2.11 uyarınca ayrıştırma sırasında `\n` olur ve kanonik çıktıda
   * `&#xD;` görünmez. Yalnızca `&#xD;` diye YAZILMIŞ olan görünür.
   */
  it('düz CRLF normalize edilir, karakter başvurusu korunur', () => {
    expect(c14n('<a>\r\nb\r\n</a>')).toBe('<a>\nb\n</a>')
    expect(c14n('<a>&#xD;\nb</a>')).toBe('<a>&#xD;\nb</a>')
    expect(c14n('<a>\rb</a>')).toBe('<a>\nb</a>')
  })

  it('öznitelikte düz boşluk tek boşluğa iner, başvuru inmez', () => {
    expect(c14n('<a x="1\t2\n3"/>')).toBe('<a x="1 2 3"></a>')
    expect(c14n('<a x="1&#x9;2&#xA;3"/>')).toBe('<a x="1&#x9;2&#xA;3"></a>')
  })
})

describe('Exclusive C14N', () => {
  const exc = (xml: string, options?: { prefixes?: readonly string[] }): string =>
    canonicalize(parseXml(xml), {
      algorithm: 'exc-c14n',
      ...(options?.prefixes === undefined ? {} : { inclusiveNamespacePrefixes: options.prefixes }),
    })

  it('kullanılmayan ad alanı bildirimlerini atar', () => {
    // `unused` hiçbir öğe ya da öznitelikte geçmiyor; dışlayıcı biçim onu yazmaz.
    expect(exc('<a xmlns:unused="urn:x" xmlns="urn:a"><b/></a>')).toBe(
      '<a xmlns="urn:a"><b></b></a>',
    )
  })

  it('öznitelikte kullanılan ön eki tutar', () => {
    expect(exc('<a xmlns:p="urn:p" p:x="1"/>')).toBe('<a xmlns:p="urn:p" p:x="1"></a>')
  })

  it('PrefixList ile kullanılmayan ön ek de yazılır', () => {
    expect(exc('<a xmlns:soap="urn:s" xmlns="urn:a"/>', { prefixes: ['soap'] })).toBe(
      '<a xmlns="urn:a" xmlns:soap="urn:s"></a>',
    )
  })

  it('PrefixList içindeki #default varsayılan ad alanını gösterir', () => {
    const doc = parseXml('<a xmlns="urn:a"><b xmlns=""/></a>')
    const b = childNamed(doc.root, '', 'b') ?? [...walkElements(doc.root)][1]!
    expect(
      canonicalize(doc, {
        algorithm: 'exc-c14n',
        subset: b,
        inclusiveNamespacePrefixes: ['#default'],
      }),
    ).toBe('<b></b>')
  })

  it('kapsayıcı biçimin aksine kullanılmayan ata ad alanını taşımaz', () => {
    const doc = parseXml('<r xmlns:extra="urn:e" xmlns:p="urn:p"><p:target><p:x/></p:target></r>')
    const target = [...walkElements(doc.root)].find((e) => e.localName === 'target')!

    expect(canonicalize(doc, { algorithm: 'exc-c14n', subset: target })).toBe(
      '<p:target xmlns:p="urn:p"><p:x></p:x></p:target>',
    )
    // Kapsayıcı biçim, kullanılmayan `extra`yı da tepe öğeye taşır.
    expect(canonicalize(doc, { algorithm: 'c14n10', subset: target })).toBe(
      '<p:target xmlns:extra="urn:e" xmlns:p="urn:p"><p:x></p:x></p:target>',
    )
  })
})

describe('alt küme ve ata bağlamı', () => {
  /**
   * `xmldsigjs#59`: kök öğede ön ek varsa imza geçersiz oluyordu. Sebep,
   * alt ağaç kanonikleştirilirken ata ad alanı bağlamının kaybolmasıydı.
   * Burada bağlam belgeden okunduğu için kaybolacak bir şey yok.
   */
  it('kökte ön ek varken alt ağaç doğru bağlamla yazılır', () => {
    const doc = parseXml(
      '<ns2:Root xmlns="urn:default" xmlns:ns2="urn:two"><ns2:Child><Leaf>x</Leaf></ns2:Child></ns2:Root>',
    )
    const child = [...walkElements(doc.root)].find((e) => e.localName === 'Child')!
    expect(canonicalize(doc, { algorithm: 'c14n10', subset: child })).toBe(
      '<ns2:Child xmlns="urn:default" xmlns:ns2="urn:two"><Leaf>x</Leaf></ns2:Child>',
    )
  })

  it('kapsayıcı biçim ata xml:* özniteliklerini tepe öğeye taşır', () => {
    const doc = parseXml('<r xml:lang="tr" xml:space="preserve"><c>x</c></r>')
    const c = [...walkElements(doc.root)].find((e) => e.localName === 'c')!
    expect(canonicalize(doc, { algorithm: 'c14n10', subset: c })).toBe(
      '<c xml:lang="tr" xml:space="preserve">x</c>',
    )
    // Dışlayıcı biçim bunu KASTEN yapmaz — alt ağacı bağlamından koparmak
    // exclusive c14n'in var oluş nedenidir.
    expect(canonicalize(doc, { algorithm: 'exc-c14n', subset: c })).toBe('<c>x</c>')
  })

  it('öğenin kendi xml:* özniteliği atadakini gölgeler', () => {
    const doc = parseXml('<r xml:lang="tr"><c xml:lang="en">x</c></r>')
    const c = [...walkElements(doc.root)].find((e) => e.localName === 'c')!
    expect(canonicalize(doc, { algorithm: 'c14n10', subset: c })).toBe('<c xml:lang="en">x</c>')
  })

  /**
   * e-Fatura'nın gerçek yolu: imzalanan `xades:SignedProperties` her zaman
   * belgenin ORTASINDA bir alt kümedir ve `ds:Reference URI="#…"` onu
   * gösterir. Kapsayıcı biçim seçildiğinde ata ad alanı bildirimlerinin
   * tepe öğeye taşınması ŞARTTIR.
   *
   * Ölçüldü (xmldsigjs 2.8.8, Eylül 2026): tam belge kanonikleştirmesinde
   * libxml2 ile birebir aynı, ama alt kümede ata bildirimlerini taşımıyor —
   * aşağıdaki beklentinin yerine `<Hedef xmlns="urn:ubl:Invoice-2" Id="x">
   * <cbc:ID xmlns:cbc="urn:ubl:cbc">1</cbc:ID></Hedef>` üretiyor. Özet
   * farklı çıkar, imza tutmaz.
   */
  it('UBL uzantısı içindeki alt küme ata bildirimlerini taşır', () => {
    const doc = parseXml(
      '<Invoice xmlns="urn:ubl:Invoice-2" xmlns:cbc="urn:ubl:cbc" xmlns:ext="urn:ubl:ext">' +
        '<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent>' +
        '<Hedef Id="x"><cbc:ID>1</cbc:ID></Hedef>' +
        '</ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions></Invoice>',
    )
    const hedef = [...walkElements(doc.root)].find((e) => e.localName === 'Hedef')!

    expect(canonicalize(doc, { algorithm: 'c14n10', subset: hedef })).toBe(
      '<Hedef xmlns="urn:ubl:Invoice-2" xmlns:cbc="urn:ubl:cbc" xmlns:ext="urn:ubl:ext" Id="x">' +
        '<cbc:ID>1</cbc:ID></Hedef>',
    )
    // Dışlayıcı biçim kullanılmayan `ext`i atar; `cbc` alt öğede bildirilir.
    expect(canonicalize(doc, { algorithm: 'exc-c14n', subset: hedef })).toBe(
      '<Hedef xmlns="urn:ubl:Invoice-2" Id="x"><cbc:ID xmlns:cbc="urn:ubl:cbc">1</cbc:ID></Hedef>',
    )
  })

  it('miras yalnızca tepe öğeye uygulanır, alt öğelere tekrarlanmaz', () => {
    const doc = parseXml('<r xml:lang="tr"><c><d>x</d></c></r>')
    const c = [...walkElements(doc.root)].find((e) => e.localName === 'c')!
    expect(canonicalize(doc, { algorithm: 'c14n10', subset: c })).toBe(
      '<c xml:lang="tr"><d>x</d></c>',
    )
  })
})

describe('düğüm çıkarma (enveloped-signature dönüşümü)', () => {
  /**
   * `xmldsigjs#49` ve `#37`: dönüşüm belgedeki BÜTÜN imzaları siliyordu.
   * Doğrusu, referansı içeren imzayı silmektir; kardeş imzalar belgede kalır
   * ve imzalanan baytların parçasıdır. Aksi hâlde paralel imza (`xadesjs#87`)
   * hiç çalışmaz: ikinci imzacı, birincinin imzasını görmediği için farklı
   * bir özet hesaplar.
   */
  it('yalnızca verilen imzayı çıkarır, kardeşini bırakır', () => {
    const doc = parseXml('<r><a/><Signature>ilk</Signature><Signature>ikinci</Signature></r>')
    const signatures = [...walkElements(doc.root)].filter((e) => e.localName === 'Signature')
    expect(signatures).toHaveLength(2)

    expect(canonicalize(doc, { algorithm: 'exc-c14n', omit: new Set([signatures[0]!]) })).toBe(
      '<r><a></a><Signature>ikinci</Signature></r>',
    )
    expect(canonicalize(doc, { algorithm: 'exc-c14n', omit: new Set([signatures[1]!]) })).toBe(
      '<r><a></a><Signature>ilk</Signature></r>',
    )
  })
})

describe('programla kurulmuş düğümler', () => {
  /**
   * Ayrıştırıcıdan geçen bir belgede yorum içinde CR bulunamaz: satır sonu
   * normalizasyonu önce çalışır, yorumlar da karakter başvurusu tanımaz.
   * Ama imza yapıları bellekte kurulur; oraya CR taşıyan bir yorum konabilir
   * ve kanonik biçim onu `&#xD;` diye yazmak zorundadır.
   */
  it('yorum ve yönergedeki satır başı karakter başvurusuna dönüşür', () => {
    const document: XmlDocument = {
      kind: 'document',
      root: {
        kind: 'element',
        namespace: undefined,
        prefix: undefined,
        localName: 'r',
        namespaceDeclarations: [],
        attributes: [],
        children: [
          { kind: 'comment', value: 'bir\riki' },
          { kind: 'pi', target: 'p', value: 'a\rb' },
        ],
      },
      prolog: [],
      epilog: [],
    }

    expect(canonicalize(document, { algorithm: 'exc-c14n-with-comments' })).toBe(
      '<r><!--bir&#xD;iki--><?p a&#xD;b?></r>',
    )
  })
})

describe('algoritma URI eşlemesi', () => {
  it('her algoritma için URI ileri ve geri çevrilir', () => {
    for (const [key, uri] of Object.entries(C14N_URI)) {
      expect(c14nAlgorithmFromUri(uri)).toBe(key)
    }
  })

  it('tanınmayan URI reddedilir', () => {
    expect(() => c14nAlgorithmFromUri('urn:bilinmeyen')).toThrow(/Desteklenmeyen/)
  })
})
