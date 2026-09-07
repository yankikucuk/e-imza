import { deflateSync } from 'node:zlib'

import { concat, utf8 } from '../src/core/bytes.js'

/**
 * En küçük geçerli PDF'i üretir.
 *
 * Testler için elle üretilmiş bir dosya, hazır bir kütüphaneden gelenden
 * daha iyi: konumlar deterministik, yapı tam olarak bilinen ve dış bir
 * araca bağımlı değil. `pdfsig` gibi bağımsız doğrulayıcılar bu dosyayı
 * sorunsuz okuyor.
 */
export const minimalPdf = (options: { readonly pages?: number } = {}): Uint8Array => {
  const pageCount = options.pages ?? 1
  const bodies: string[] = []

  const pageRefs = Array.from({ length: pageCount }, (_, i) => `${String(3 + i)} 0 R`).join(' ')
  bodies.push('<< /Type /Catalog /Pages 2 0 R >>')
  bodies.push(`<< /Type /Pages /Kids [${pageRefs}] /Count ${String(pageCount)} >>`)
  for (let i = 0; i < pageCount; i += 1) {
    bodies.push('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>')
  }

  const parts: Uint8Array[] = [utf8('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')]
  let offset = parts[0]?.length ?? 0
  const offsets: number[] = []

  for (const [index, body] of bodies.entries()) {
    offsets.push(offset)
    const chunk = utf8(`${String(index + 1)} 0 obj\n${body}\nendobj\n`)
    parts.push(chunk)
    offset += chunk.length
  }

  const xrefOffset = offset
  let xref = `xref\n0 ${String(bodies.length + 1)}\n0000000000 65535 f \n`
  for (const position of offsets) {
    xref += `${String(position).padStart(10, '0')} 00000 n \n`
  }
  parts.push(
    utf8(xref),
    utf8(
      `trailer\n<< /Size ${String(bodies.length + 1)} /Root 1 0 R >>\n` +
        `startxref\n${String(xrefOffset)}\n%%EOF\n`,
    ),
  )
  return concat(...parts)
}

/**
 * Çapraz başvuru **akışı** kullanan bir PDF üretir (PDF 1.5+).
 *
 * Klasik `xref` tablosu yerine sıkıştırılmış bir akış kullanılıyor ve
 * sayfa ile katalog bir **nesne akışının** (`ObjStm`) içinde duruyor.
 * Modern üreticilerin çıktısı böyle; bu yolun dış bir araca bağımlı
 * olmadan sınanması gerekiyor çünkü belge kökünü bulmak tamamen buna
 * bağlı.
 */
export const pdfWithXrefStream = (): Uint8Array => {
  // Nesne akışının içeriği: 1 (katalog), 2 (sayfa ağacı), 3 (sayfa).
  const inner = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>',
  ]
  let header = ''
  let body = ''
  for (const [index, text] of inner.entries()) {
    header += `${String(index + 1)} ${String(body.length)} `
    body += `${text} `
  }
  const objStmData = deflateSync(Buffer.from(header + body, 'latin1'))

  const parts: Uint8Array[] = [utf8('%PDF-1.5\n%\xe2\xe3\xcf\xd3\n')]
  let offset = parts[0]?.length ?? 0

  // 4 0 obj — nesne akışı.
  const objStmOffset = offset
  const objStmHead = utf8(
    `4 0 obj\n<< /Type /ObjStm /N ${String(inner.length)} /First ${String(header.length)} ` +
      `/Length ${String(objStmData.length)} /Filter /FlateDecode >>\nstream\n`,
  )
  const objStmTail = utf8('\nendstream\nendobj\n')
  parts.push(objStmHead, new Uint8Array(objStmData), objStmTail)
  offset += objStmHead.length + objStmData.length + objStmTail.length

  // 5 0 obj — çapraz başvuru akışı. /W [1 4 2], PNG öngörücüsü YOK.
  const xrefOffset = offset
  const rows: number[] = []
  const push = (type: number, second: number, third: number): void => {
    rows.push(type)
    rows.push((second >>> 24) & 0xff, (second >>> 16) & 0xff, (second >>> 8) & 0xff, second & 0xff)
    rows.push((third >>> 8) & 0xff, third & 0xff)
  }
  push(0, 0, 0xffff) // 0: serbest
  push(2, 4, 0) // 1: nesne akışı 4, sıra 0
  push(2, 4, 1) // 2
  push(2, 4, 2) // 3
  push(1, objStmOffset, 0) // 4
  push(1, xrefOffset, 0) // 5
  const xrefData = deflateSync(Buffer.from(new Uint8Array(rows)))

  const xrefHead = utf8(
    `5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R ` +
      `/Length ${String(xrefData.length)} /Filter /FlateDecode >>\nstream\n`,
  )
  parts.push(xrefHead, new Uint8Array(xrefData), utf8('\nendstream\nendobj\n'))
  parts.push(utf8(`startxref\n${String(xrefOffset)}\n%%EOF\n`))
  return concat(...parts)
}

/**
 * PNG öngörücüsü (`Predictor 12`) kullanan çapraz başvuru akışı.
 *
 * Gerçek üreticilerin çıktısı neredeyse her zaman böyle: satırlar bir
 * önceki satırın farkı olarak kodlanır. Geri alınmazsa tablo sessizce
 * yanlış okunur — hata vermez, sadece yanlış konumlar döner.
 */
export const pdfWithPredictor = (): Uint8Array => {
  const bodies = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>',
  ]
  const parts: Uint8Array[] = [utf8('%PDF-1.5\n%\xe2\xe3\xcf\xd3\n')]
  let offset = parts[0]?.length ?? 0
  const offsets: number[] = []
  for (const [index, body] of bodies.entries()) {
    offsets.push(offset)
    const chunk = utf8(`${String(index + 1)} 0 obj\n${body}\nendobj\n`)
    parts.push(chunk)
    offset += chunk.length
  }

  const xrefOffset = offset
  // /W [1 4 2] → satır genişliği 7. Serbest girdi + üç nesne + akışın kendisi.
  const columns = 7
  const raw: number[][] = []
  const row = (type: number, second: number, third: number): number[] => [
    type,
    (second >>> 24) & 0xff,
    (second >>> 16) & 0xff,
    (second >>> 8) & 0xff,
    second & 0xff,
    (third >>> 8) & 0xff,
    third & 0xff,
  ]
  raw.push(row(0, 0, 0xffff))
  for (const position of offsets) raw.push(row(1, position, 0))
  raw.push(row(1, xrefOffset, 0))

  // PNG "Up" süzgeci: her satır bir öncekinden çıkarılır, başına tür baytı.
  const encoded: number[] = []
  let previous = new Array<number>(columns).fill(0)
  for (const current of raw) {
    encoded.push(2)
    for (let i = 0; i < columns; i += 1) {
      encoded.push(((current[i] ?? 0) - (previous[i] ?? 0)) & 0xff)
    }
    previous = current
  }
  const data = deflateSync(Buffer.from(new Uint8Array(encoded)))

  const head = utf8(
    `${String(bodies.length + 1)} 0 obj\n<< /Type /XRef /Size ${String(bodies.length + 2)} ` +
      `/W [1 4 2] /Root 1 0 R /Filter /FlateDecode ` +
      `/DecodeParms << /Predictor 12 /Columns ${String(columns)} >> ` +
      `/Length ${String(data.length)} >>\nstream\n`,
  )
  parts.push(head, new Uint8Array(data), utf8('\nendstream\nendobj\n'))
  parts.push(utf8(`startxref\n${String(xrefOffset)}\n%%EOF\n`))
  return concat(...parts)
}
