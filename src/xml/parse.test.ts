import { describe, expect, it } from 'vitest'

import {
  DoctypeNotAllowedError,
  UnboundPrefixError,
  XmlLimitExceededError,
  XmlSyntaxError,
} from '../core/errors.js'

import { replaceElement, findElementById, appendChildren } from './edit.js'
import {
  childElements,
  childNamed,
  childrenNamed,
  getAttribute,
  getAttributeValue,
  qualifiedName,
  textContent,
  walkElements,
  XML_NAMESPACE,
  XMLNS_NAMESPACE,
} from './node.js'
import { parseXml } from './parse.js'
import { serializeElement, serializeXml } from './serialize.js'

describe('ad alanı çözümlemesi', () => {
  it('varsayılan ad alanı öğelere miras kalır', () => {
    const doc = parseXml('<a xmlns="urn:a"><b/></a>')
    expect(doc.root.namespace).toBe('urn:a')
    expect(childElements(doc.root)[0]?.namespace).toBe('urn:a')
  })

  /**
   * Namespaces in XML 1.0 §6.2: ön eksiz ÖZNİTELİK varsayılan ad alanına
   * bağlanmaz. Bu asimetri sıkça yanlış uygulanır ve kanonik sıralamayı
   * bozar — ad alanısız öznitelikler her zaman en başa gelmelidir.
   */
  it('ön eksiz öznitelik varsayılan ad alanını MİRAS ALMAZ', () => {
    const doc = parseXml('<a xmlns="urn:a" x="1"/>')
    expect(getAttribute(doc.root, 'x')?.namespace).toBeUndefined()
  })

  it('ön ekli öznitelik kendi ad alanına bağlanır', () => {
    const doc = parseXml('<a xmlns:p="urn:p" p:x="1"/>')
    expect(getAttribute(doc.root, 'x', 'urn:p')?.value).toBe('1')
  })

  it('xml ön eki bildirilmeden çalışır', () => {
    const doc = parseXml('<a xml:lang="tr"/>')
    expect(getAttributeValue(doc.root, 'lang', XML_NAMESPACE)).toBe('tr')
  })

  it('xmlns ön eki sabit ad alanına bağlıdır', () => {
    const doc = parseXml('<a xmlns:p="urn:p" p:x="1"/>')
    expect(XMLNS_NAMESPACE).toBe('http://www.w3.org/2000/xmlns/')
    expect(doc.root.namespaceDeclarations).toStrictEqual([{ prefix: 'p', uri: 'urn:p' }])
  })

  it('bildirilmemiş ön ek reddedilir', () => {
    expect(() => parseXml('<p:a/>')).toThrow(UnboundPrefixError)
    expect(() => parseXml('<a p:x="1"/>')).toThrow(UnboundPrefixError)
  })

  it('iptal edilmiş varsayılan ad alanı öğeyi ad alanısız yapar', () => {
    const doc = parseXml('<a xmlns="urn:a"><b xmlns=""/></a>')
    expect(childElements(doc.root)[0]?.namespace).toBeUndefined()
  })
})

describe('içerik ayrıştırma', () => {
  it('CDATA metne indirgenir', () => {
    expect(textContent(parseXml('<a><![CDATA[<x> & </x>]]></a>').root)).toBe('<x> & </x>')
  })

  it('önceden tanımlı varlıklar çözülür', () => {
    expect(textContent(parseXml('<a>&amp;&lt;&gt;&quot;&apos;</a>').root)).toBe('&<>"\'')
  })

  it('karakter başvuruları onlu ve onaltılık çözülür', () => {
    expect(textContent(parseXml('<a>&#65;&#x42;&#x1F600;</a>').root)).toBe('AB😀')
  })

  it('karışık içerik korunur', () => {
    const doc = parseXml('<a>önce<b/>sonra</a>')
    expect(doc.root.children.map((child) => child.kind)).toStrictEqual(['text', 'element', 'text'])
  })

  it('yorum ve işlem yönergeleri korunur', () => {
    const doc = parseXml('<?pi veri?><!--üst--><a><!--iç--><?p2?></a><!--alt-->')
    expect(doc.prolog).toHaveLength(2)
    expect(doc.epilog).toHaveLength(1)
    expect(doc.root.children.map((child) => child.kind)).toStrictEqual(['comment', 'pi'])
  })

  it('bayt sırası işareti atlanır', () => {
    expect(parseXml('﻿<a/>').root.localName).toBe('a')
  })

  it("XML bildirimi prolog'a girmez", () => {
    const doc = parseXml('<?xml version="1.0" encoding="UTF-8"?><a/>')
    expect(doc.prolog).toHaveLength(0)
  })
})

describe('iyi-biçimlilik denetimleri', () => {
  const bad: readonly (readonly [string, string])[] = [
    ['kapanmamış öğe', '<a>'],
    ['eşleşmeyen kapanış', '<a></b>'],
    ['birden çok kök', '<a/><b/>'],
    ['kök dışında metin', 'metin<a/>'],
    ['kök yok', '   '],
    ['tanımsız varlık', '<a>&yok;</a>'],
    ['boş karakter başvurusu', '<a>&#;</a>'],
    ['tırnaksız öznitelik', '<a x=1/>'],
    ['kapanmamış öznitelik', '<a x="1/>'],
    ['öznitelikte açı parantezi', '<a x="<"/>'],
    ['yinelenen öznitelik', '<a x="1" x="2"/>'],
    ['geçersiz nitelenmiş ad', '<a:b:c xmlns:a="urn:a"/>'],
    ['kapanmamış yorum', '<a><!-- x</a>'],
    ['yorumda çift tire', '<a><!-- x -- y --></a>'],
    ['kapanmamış CDATA', '<a><![CDATA[x</a>'],
    ['kapanmamış yönerge', '<a><?p x</a>'],
    ['öğe içinde bildirim', '<a><!ENTITY x "y"></a>'],
    ['kaçırılmamış ]]>', '<a>]]></a>'],
    ['XML dışı karakter başvurusu', '<a>&#x0;</a>'],
  ]

  for (const [name, xml] of bad) {
    it(`reddedilir: ${name}`, () => {
      expect(() => parseXml(xml)).toThrow(XmlSyntaxError)
    })
  }

  it('DOCTYPE ayrı bir hata sınıfıyla reddedilir', () => {
    expect(() => parseXml('<!DOCTYPE a><a/>')).toThrow(DoctypeNotAllowedError)
  })
})

describe('kaynak sınırları', () => {
  it('boyut sınırı ayrıştırmadan önce uygulanır', () => {
    expect(() => parseXml('<a/>', { maxSize: 2 })).toThrow(XmlLimitExceededError)
  })

  it('derinlik sınırı uygulanır', () => {
    const deep = '<a>'.repeat(30) + '</a>'.repeat(30)
    expect(() => parseXml(deep, { maxDepth: 10 })).toThrow(XmlLimitExceededError)
    expect(() => parseXml(deep, { maxDepth: 40 })).not.toThrow()
  })
})

describe('serileştirme', () => {
  /**
   * Gidiş-dönüş güvenliği: ürettiğimiz metin yeniden okunduğunda birebir
   * aynı ağacı vermeli. `&#xD;` düz CR olarak yazılırsa, belge bir daha
   * okunduğunda satır sonu normalizasyonu onu `\n` yapar ve imza tutmaz.
   */
  it('ağaç, metin ve tekrar ağaç aynı kalır', () => {
    const sources = [
      '<a x="1"><b>metin</b></a>',
      '<a xmlns="urn:a" xmlns:p="urn:p"><p:b p:x="1"/></a>',
      '<a>&#xD;satır</a>',
      '<a x="sekme&#x9;ve&#xA;satır"/>',
      '<a>Ç &amp; Ş &lt; Ğ &gt; "tırnak"</a>',
      '<a><!--yorum--><?pi veri?>karışık<b/>içerik</a>',
      '<a/>',
    ]
    for (const source of sources) {
      const once = parseXml(source)
      const text = serializeXml(once)
      const twice = parseXml(text)
      expect(serializeXml(twice)).toBe(text)
      expect(textContent(twice.root)).toBe(textContent(once.root))
    }
  })

  it('CR karakteri başvuruya dönüştürülerek yazılır', () => {
    expect(serializeXml(parseXml('<a>&#xD;</a>'), { declaration: null })).toBe('<a>&#xD;</a>')
  })

  it('bildirim yazılmayabilir ve değiştirilebilir', () => {
    expect(serializeXml(parseXml('<a/>'), { declaration: null })).toBe('<a/>')
    expect(serializeXml(parseXml('<a/>'), { declaration: '<?xml version="1.0"?>' })).toBe(
      '<?xml version="1.0"?>\n<a/>',
    )
  })

  it('kök dışı düğümler korunur', () => {
    const text = serializeXml(parseXml('<!--üst--><a/><!--alt-->'), { declaration: null })
    expect(text).toBe('<!--üst-->\n<a/>\n<!--alt-->')
  })

  it('tek öğe ayrı serileştirilebilir', () => {
    const doc = parseXml('<a><b x="1">m</b></a>')
    expect(serializeElement(childElements(doc.root)[0]!)).toBe('<b x="1">m</b>')
  })
})

describe('düğüm yardımcıları', () => {
  const doc = parseXml(
    '<r xmlns="urn:r" xmlns:p="urn:p"><a>1</a><a>2</a><p:a>3</p:a><b><c>iç</c></b></r>',
  )

  it('adla alt öğe bulur', () => {
    expect(childrenNamed(doc.root, 'urn:r', 'a')).toHaveLength(2)
    expect(childrenNamed(doc.root, 'urn:p', 'a')).toHaveLength(1)
    expect(childNamed(doc.root, 'urn:r', 'yok')).toBeUndefined()
  })

  it('nitelenmiş ad üretir', () => {
    expect(qualifiedName(doc.root)).toBe('r')
    expect(qualifiedName(childNamed(doc.root, 'urn:p', 'a')!)).toBe('p:a')
  })

  it('alt ağaçtaki metni birleştirir', () => {
    expect(textContent(doc.root)).toBe('123iç')
  })

  it('belge sırasında dolaşır', () => {
    expect([...walkElements(doc.root)].map((element) => element.localName)).toStrictEqual([
      'r',
      'a',
      'a',
      'a',
      'b',
      'c',
    ])
  })
})

describe('ağaç düzenleme', () => {
  it('öğe değiştirilince yalnızca yol yeniden kurulur', () => {
    const doc = parseXml('<r><a><b/></a><c/></r>')
    const target = childNamed(doc.root, undefined, 'a')!
    const other = childNamed(doc.root, undefined, 'c')!
    const next = replaceElement(doc, target, { ...target, children: [] })

    expect(serializeXml(next, { declaration: null })).toBe('<r><a/><c/></r>')
    // Dokunulmayan dal aynı NESNE olarak kalır — yapısal paylaşım.
    expect(childNamed(next.root, undefined, 'c')).toBe(other)
  })

  it('bulunamayan hedef belgeyi değiştirmez', () => {
    const doc = parseXml('<r/>')
    const yabancı = parseXml('<x/>').root
    expect(replaceElement(doc, yabancı, yabancı)).toBe(doc)
  })

  it('alt düğüm ekler', () => {
    const doc = parseXml('<r><a/></r>')
    const next = appendChildren(doc, doc.root, parseXml('<b/>').root)
    expect(serializeXml(next, { declaration: null })).toBe('<r><a/><b/></r>')
  })

  /**
   * Kimlik belirsizse `undefined` döner. "İlkini al" demek, saldırganın
   * araya kendi öğesini koyup imzanın kapsamını kaydırmasına izin vermek
   * olurdu — imza sarma (signature wrapping) saldırısının klasik biçimi.
   */
  it('kimlikle öğe bulur', () => {
    const doc = parseXml('<r><a Id="x"/><b ID="y"/><c id="z"/><d xml:id="w"/></r>')
    expect(findElementById(doc, 'x')?.localName).toBe('a')
    expect(findElementById(doc, 'y')?.localName).toBe('b')
    expect(findElementById(doc, 'z')?.localName).toBe('c')
    expect(findElementById(doc, 'w')?.localName).toBe('d')
    expect(findElementById(doc, 'yok')).toBeUndefined()
  })

  it('yinelenen kimlik belirsizdir ve reddedilir', () => {
    const doc = parseXml('<r><a Id="x"/><b Id="x"/></r>')
    expect(findElementById(doc, 'x')).toBeUndefined()
  })
})
