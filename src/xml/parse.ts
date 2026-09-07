import {
  DoctypeNotAllowedError,
  UnboundPrefixError,
  XmlLimitExceededError,
  XmlSyntaxError,
} from '../core/errors.js'

import {
  XML_NAMESPACE,
  XMLNS_NAMESPACE,
  type XmlAttribute,
  type XmlComment,
  type XmlDocument,
  type XmlElement,
  type XmlNamespaceDeclaration,
  type XmlNode,
  type XmlProcessingInstruction,
} from './node.js'

/** {@link parseXml} seçenekleri. */
export interface ParseOptions {
  /**
   * İzin verilen en fazla iç içe geçme derinliği. Varsayılan 200.
   *
   * İmzalı belge karşı taraftan gelir; derinliğini gönderen belirler.
   * Sınırsız derinlik, özyinelemeli dolaşmada yığın taşmasıdır.
   */
  readonly maxDepth?: number

  /**
   * İzin verilen en fazla girdi uzunluğu (karakter). Varsayılan 33.554.432 (32 MiB).
   *
   * Sınır ayrıştırmadan ÖNCE uygulanır; hiçbir iş yapmadan reddetmek,
   * yarı yolda bellek tüketmekten iyidir.
   */
  readonly maxSize?: number
}

const DEFAULT_MAX_DEPTH = 200
const DEFAULT_MAX_SIZE = 32 * 1024 * 1024

/** XML'in beş önceden tanımlı varlığı. DTD reddedildiği için başkası olamaz. */
const PREDEFINED: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
}

/** XML 1.0 §2.3 `S` — boşluk sayılan dört karakter. */
const isSpace = (code: number): boolean =>
  code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d

/** `NameStartChar` (XML 1.0 §2.3), yaygın aralıklarla. */
const isNameStart = (code: number): boolean =>
  code === 0x3a || // ':'
  code === 0x5f || // '_'
  (code >= 0x41 && code <= 0x5a) ||
  (code >= 0x61 && code <= 0x7a) ||
  (code >= 0xc0 && code <= 0xd6) ||
  (code >= 0xd8 && code <= 0xf6) ||
  (code >= 0xf8 && code <= 0x2ff) ||
  (code >= 0x370 && code <= 0x37d) ||
  (code >= 0x37f && code <= 0x1fff) ||
  (code >= 0x200c && code <= 0x200d) ||
  (code >= 0x2070 && code <= 0x218f) ||
  (code >= 0x2c00 && code <= 0x2fef) ||
  (code >= 0x3001 && code <= 0xd7ff) ||
  (code >= 0xf900 && code <= 0xfdcf) ||
  (code >= 0xfdf0 && code <= 0xfffd) ||
  (code >= 0x10000 && code <= 0xeffff)

/** `NameChar` — `NameStartChar` artı rakamlar, `-`, `.` ve birleştirici işaretler. */
const isNameChar = (code: number): boolean =>
  isNameStart(code) ||
  code === 0x2d || // '-'
  code === 0x2e || // '.'
  code === 0xb7 ||
  (code >= 0x30 && code <= 0x39) ||
  (code >= 0x300 && code <= 0x36f) ||
  (code >= 0x203f && code <= 0x2040)

/**
 * XML 1.0 §2.11 satır sonu normalizasyonu.
 *
 * `\r\n` ve tek başına `\r`, ayrıştırma başlamadan ÖNCE `\n`'e çevrilir.
 * Bu adımın sırası kritiktir: kaynakta yazılı `&#xD;` başvurusu bu aşamada
 * hâlâ altı karakterlik düz metindir, dolayısıyla normalizasyondan etkilenmez
 * ve varlık çözümünde gerçek bir `\r` olarak geri gelir. Kanonik çıktıda
 * `&#xD;` olarak yazılması gereken tek karakter işte odur.
 *
 * `xml-crypto#238` bu ayrımı yapmadığı için kaynaktaki her `\r\n`'i `&#xD;\n`
 * diye kanonikleştiriyor ve hiçbir uyumlu uygulamayla eşleşmeyen bir özet
 * üretiyordu.
 */
const normalizeLineEndings = (xml: string): string => xml.replace(/\r\n?/g, '\n')

/** Ayrıştırma sırasında ad alanı kapsamı — ön ek → URI. */
type Scope = ReadonlyMap<string, string>

/**
 * XML belgesini imza-sadık düğüm ağacına ayrıştırır.
 *
 * Yorumlar, işlem yönergeleri ve karışık içerik korunur; CDATA bölümleri
 * metne indirgenir (kanonik biçimde CDATA diye bir şey yoktur).
 *
 * @param xml - Ayrıştırılacak belge
 * @param options - Derinlik ve boyut sınırları
 * @returns Kök öğe ile kök öncesi/sonrası yorum ve yönergeler
 * @throws {XmlSyntaxError} Belge iyi-biçimli değilse
 * @throws {DoctypeNotAllowedError} Belgede DOCTYPE bildirimi varsa
 * @throws {XmlLimitExceededError} Boyut ya da derinlik sınırı aşılırsa
 * @throws {UnboundPrefixError} Bildirilmemiş bir ön ek kullanılmışsa
 *
 * @example
 * ```ts
 * const doc = parseXml('<Invoice xmlns="urn:…:Invoice-2"><cbc:ID>1</cbc:ID></Invoice>')
 * doc.root.localName // 'Invoice'
 * ```
 */
export const parseXml = (xml: string, options: ParseOptions = {}): XmlDocument => {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH
  const maxSize = options.maxSize ?? DEFAULT_MAX_SIZE
  if (xml.length > maxSize) throw new XmlLimitExceededError('size', xml.length, maxSize)

  const source = normalizeLineEndings(xml)
  let at = 0

  // Değişkenin KENDİSİ `never` dönüşlü olarak imzalanmalı: TypeScript, ok
  // fonksiyonunun dönüş tipi açıkça `never` olsa bile, bildirimde tip
  // ek açıklaması yoksa çağrıyı akış analizinde sonlandırıcı saymaz.
  const fail: (detail: string) => never = (detail) => {
    throw new XmlSyntaxError(at, detail)
  }

  const skipSpace = (): void => {
    while (at < source.length && isSpace(source.charCodeAt(at))) at += 1
  }

  const expect = (literal: string): void => {
    if (!source.startsWith(literal, at)) fail(`"${literal}" bekleniyordu.`)
    at += literal.length
  }

  const readName = (): string => {
    const start = at
    if (at >= source.length || !isNameStart(source.codePointAt(at) ?? 0)) fail('Ad bekleniyordu.')
    while (at < source.length) {
      const code = source.codePointAt(at) ?? 0
      if (!isNameChar(code)) break
      at += code > 0xffff ? 2 : 1
    }
    return source.slice(start, at)
  }

  /**
   * Tek bir `&…;` başvurusunu çözer.
   *
   * Yalnızca beş önceden tanımlı varlık ve karakter başvuruları kabul edilir;
   * DTD reddedildiği için başka bir varlık tanımlanmış olamaz. Tanımsız bir
   * varlığı sessizce metin olarak bırakmak, imzalanan ile doğrulananın
   * ayrışmasına yol açacağı için hata sayılır.
   */
  const readReference = (): string => {
    expect('&')
    if (source[at] === '#') {
      at += 1
      const hex = source[at] === 'x'
      if (hex) at += 1
      const start = at
      while (at < source.length && source[at] !== ';') at += 1
      const digits = source.slice(start, at)
      expect(';')
      if (digits === '') fail('Boş karakter başvurusu.')
      const code = Number.parseInt(digits, hex ? 16 : 10)
      if (!Number.isFinite(code) || !/^[0-9a-fA-F]+$/.test(digits)) {
        fail(`Geçersiz karakter başvurusu: &#${hex ? 'x' : ''}${digits};`)
      }
      // XML 1.0 §2.2 `Char` — bunun dışındaki kod noktaları belgede yer alamaz.
      const valid =
        code === 0x09 ||
        code === 0x0a ||
        code === 0x0d ||
        (code >= 0x20 && code <= 0xd7ff) ||
        (code >= 0xe000 && code <= 0xfffd) ||
        (code >= 0x10000 && code <= 0x10ffff)
      if (!valid) fail(`XML'de yer alamayacak karakter başvurusu: &#${digits};`)
      return String.fromCodePoint(code)
    }
    const name = readName()
    expect(';')
    const value = PREDEFINED[name]
    if (value === undefined) fail(`Tanımsız varlık başvurusu: &${name};`)
    return value
  }

  /**
   * Öznitelik değerini okur ve XML 1.0 §3.3.3 uyarınca normalize eder.
   *
   * Kaynakta DÜZ yazılmış her boşluk karakteri tek boşluğa dönüşür; karakter
   * başvurusuyla yazılmış olanlar dönüşmez. Bu ayrım korunmazsa `&#x9;`
   * içeren bir öznitelik, imzalanırken sekme, doğrulanırken boşluk olur.
   */
  const readAttributeValue = (): string => {
    const quote = source[at]
    if (quote !== '"' && quote !== "'") fail('Öznitelik değeri tırnak içinde olmalı.')
    at += 1
    let out = ''
    while (at < source.length && source[at] !== quote) {
      const char = source[at] ?? ''
      if (char === '&') {
        out += readReference()
      } else if (char === '<') {
        fail('Öznitelik değerinde "<" doğrudan yer alamaz.')
      } else if (char === '\n' || char === '\t') {
        out += ' '
        at += 1
      } else {
        out += char
        at += 1
      }
    }
    if (at >= source.length) fail('Kapanmamış öznitelik değeri.')
    at += 1
    return out
  }

  const readComment = (): XmlComment => {
    expect('<!--')
    const end = source.indexOf('-->', at)
    if (end === -1) fail('Kapanmamış yorum.')
    const value = source.slice(at, end)
    if (value.includes('--')) fail('Yorum içinde "--" dizisi yer alamaz.')
    at = end + 3
    return { kind: 'comment', value }
  }

  const readProcessingInstruction = (): XmlProcessingInstruction => {
    expect('<?')
    const target = readName()
    let value = ''
    if (at < source.length && isSpace(source.charCodeAt(at))) {
      skipSpace()
      const end = source.indexOf('?>', at)
      if (end === -1) fail('Kapanmamış işlem yönergesi.')
      value = source.slice(at, end)
      at = end
    }
    expect('?>')
    return { kind: 'pi', target, value }
  }

  const readCdata = (): string => {
    expect('<![CDATA[')
    const end = source.indexOf(']]>', at)
    if (end === -1) fail('Kapanmamış CDATA bölümü.')
    const value = source.slice(at, end)
    at = end + 3
    return value
  }

  /** Ön eki geçerli kapsamda çözer. */
  const resolvePrefix = (prefix: string, scope: Scope): string => {
    if (prefix === 'xml') return XML_NAMESPACE
    if (prefix === 'xmlns') return XMLNS_NAMESPACE
    const uri = scope.get(prefix)
    if (uri === undefined || uri === '') throw new UnboundPrefixError(prefix)
    return uri
  }

  /** Ham `ad="değer"` çiftlerini okur; ad alanı ayrımı çağırana bırakılır. */
  const readRawAttributes = (): { name: string; value: string }[] => {
    const raw: { name: string; value: string }[] = []
    for (;;) {
      skipSpace()
      const char = source[at]
      if (char === '>' || char === '/' || at >= source.length) break
      const name = readName()
      skipSpace()
      expect('=')
      skipSpace()
      raw.push({ name, value: readAttributeValue() })
    }
    return raw
  }

  const readElement = (parentScope: Scope, depth: number): XmlElement => {
    if (depth > maxDepth) throw new XmlLimitExceededError('depth', depth, maxDepth)
    expect('<')
    const openName = readName()
    const raw = readRawAttributes()

    // Ad alanı bildirimlerini normal özniteliklerden ayır. Ayrım burada,
    // bir kez yapılır; kanonikleştirici ikisini farklı sıralayacağı için
    // aşağıda tekrar "bu xmlns miydi" diye sorulacak bir yer kalmaz.
    const declarations: XmlNamespaceDeclaration[] = []
    const plain: { name: string; value: string }[] = []
    for (const attribute of raw) {
      if (attribute.name === 'xmlns') {
        declarations.push({ prefix: '', uri: attribute.value })
      } else if (attribute.name.startsWith('xmlns:')) {
        declarations.push({ prefix: attribute.name.slice(6), uri: attribute.value })
      } else {
        plain.push(attribute)
      }
    }

    const scope = new Map(parentScope)
    for (const declaration of declarations) scope.set(declaration.prefix, declaration.uri)

    const split = (name: string): { prefix: string | undefined; localName: string } => {
      const colon = name.indexOf(':')
      if (colon === -1) return { prefix: undefined, localName: name }
      const prefix = name.slice(0, colon)
      const localName = name.slice(colon + 1)
      if (prefix === '' || localName === '' || localName.includes(':')) {
        fail(`Geçersiz nitelenmiş ad: "${name}"`)
      }
      return { prefix, localName }
    }

    const { prefix, localName } = split(openName)
    // Ön eksiz ÖĞE varsayılan ad alanına bağlanır; ön eksiz ÖZNİTELİK bağlanmaz
    // (Namespaces in XML 1.0 §6.2). Bu asimetri sık sık gözden kaçar.
    const defaultUri = scope.get('') ?? ''
    const namespace =
      prefix === undefined
        ? defaultUri === ''
          ? undefined
          : defaultUri
        : resolvePrefix(prefix, scope)

    const attributes: XmlAttribute[] = plain.map((attribute) => {
      const parts = split(attribute.name)
      return {
        namespace: parts.prefix === undefined ? undefined : resolvePrefix(parts.prefix, scope),
        prefix: parts.prefix,
        localName: parts.localName,
        value: attribute.value,
      }
    })

    const seen = new Set<string>()
    for (const attribute of attributes) {
      const key = `${attribute.namespace ?? ''}#${attribute.localName}`
      if (seen.has(key)) fail(`"${openName}" öğesinde yinelenen öznitelik: ${attribute.localName}`)
      seen.add(key)
    }

    skipSpace()
    if (source.startsWith('/>', at)) {
      at += 2
      return {
        kind: 'element',
        namespace,
        prefix,
        localName,
        namespaceDeclarations: declarations,
        attributes,
        children: [],
      }
    }
    expect('>')

    const children: XmlNode[] = []
    let pending = ''
    const flush = (): void => {
      if (pending !== '') {
        children.push({ kind: 'text', value: pending })
        pending = ''
      }
    }

    for (;;) {
      if (at >= source.length) fail(`"${openName}" öğesi kapatılmamış.`)
      if (source.startsWith('</', at)) {
        at += 2
        const closeName = readName()
        if (closeName !== openName) {
          fail(`"${openName}" açıldı ama "${closeName}" kapatıldı.`)
        }
        skipSpace()
        expect('>')
        break
      }
      if (source.startsWith('<!--', at)) {
        flush()
        children.push(readComment())
      } else if (source.startsWith('<![CDATA[', at)) {
        pending += readCdata()
      } else if (source.startsWith('<?', at)) {
        flush()
        children.push(readProcessingInstruction())
      } else if (source.startsWith('<!', at)) {
        fail('Öğe içinde bildirim yer alamaz.')
      } else if (source[at] === '<') {
        flush()
        children.push(readElement(scope, depth + 1))
      } else if (source[at] === '&') {
        pending += readReference()
      } else if (source.startsWith(']]>', at)) {
        fail('İçerikte "]]>" dizisi kaçırılmadan yer alamaz.')
      } else {
        pending += source[at] ?? ''
        at += 1
      }
    }
    flush()

    return {
      kind: 'element',
      namespace,
      prefix,
      localName,
      namespaceDeclarations: declarations,
      attributes,
      children,
    }
  }

  // ── Belge düzeyi ────────────────────────────────────────────────────────
  if (source.startsWith('﻿', at)) at += 1
  if (source.startsWith('<?xml', at)) {
    const end = source.indexOf('?>', at)
    if (end === -1) fail('Kapanmamış XML bildirimi.')
    at = end + 2
  }

  const prolog: (XmlComment | XmlProcessingInstruction)[] = []
  const epilog: (XmlComment | XmlProcessingInstruction)[] = []
  let root: XmlElement | undefined

  for (;;) {
    skipSpace()
    if (at >= source.length) break
    if (source.startsWith('<!--', at)) {
      ;(root === undefined ? prolog : epilog).push(readComment())
    } else if (source.startsWith('<?', at)) {
      ;(root === undefined ? prolog : epilog).push(readProcessingInstruction())
    } else if (source.startsWith('<!DOCTYPE', at)) {
      throw new DoctypeNotAllowedError()
    } else if (source[at] === '<') {
      if (root !== undefined) fail('Belgede birden çok kök öğe var.')
      root = readElement(new Map(), 1)
    } else {
      fail('Kök öğe dışında metin yer alamaz.')
    }
  }

  if (root === undefined) fail('Belgede kök öğe yok.')
  return { kind: 'document', root, prolog, epilog }
}
