import { asSequence, decodeDer, derSetOf, type DerNode } from '../asn1/der.js'
import { SigningError } from '../core/errors.js'

/**
 * CMS yapısını **yeniden kodlamadan** düzenleme.
 *
 * Tek bir kural bu modülün tamamını açıklıyor: `signedAttrs`ın kaynaktaki
 * baytlarına DOKUNULMAZ. Yapıyı çözüp yeniden serileştirmek, kaynak DER'e
 * tam uymuyorsa (pratikte sık) o baytları değiştirir ve imza tutmaz. Bu
 * yüzden değişmeyen her alan `raw` olarak taşınır, yalnızca `unsignedAttrs`
 * yeniden kurulur.
 *
 * Hem imzanın kendisinde (T/LT/LTA öznitelikleri) hem de zaman damgası
 * JETONUNDA (`ats-hash-index`) aynı işlem gerekiyor; bu yüzden ortak.
 */

/**
 * `SignerInfo`ya imzalanmamış öznitelik ekler.
 *
 * Yapı **yeniden kodlanmaz**: `SignerInfo`nun kaynaktaki baytları alınır,
 * yalnızca `unsignedAttrs` alanı değiştirilir ve dış kaplar yeniden
 * kurulur. Yeniden kodlamak, kaynağın DER'e tam uymadığı durumlarda
 * `signedAttrs` baytlarını değiştirir ve imza tutmaz.
 */
export const addUnsignedAttributes = (
  cms: Uint8Array,
  attributes: readonly Uint8Array[],
): Uint8Array => {
  const contentInfo = asSequence(decodeDer(cms))
  const contentNode = contentInfo[1]
  if (contentNode === undefined) throw new SigningError('ContentInfo içeriği yok.')
  const signedDataNode = contentNode.children[0]
  if (signedDataNode === undefined) throw new SigningError('SignedData yok.')
  const fields = asSequence(signedDataNode)

  const signerInfosIndex = findLastSetIndex(fields)
  const signerInfosNode = fields[signerInfosIndex]
  if (signerInfosNode === undefined) throw new SigningError('signerInfos yok.')
  const signers = signerInfosNode.children
  const signer = signers[0]
  if (signer === undefined) throw new SigningError('CMS yapısında imzacı yok.')

  const signerFields = asSequence(signer)
  const unsignedIndex = signerFields.findIndex(
    (field) => field.tagClass === 'context' && field.tagNumber === 1,
  )
  // Var olan öznitelikler korunur; yenileri eklenir. Zaman damgası üstüne
  // zaman damgası eklenebilmesi bunu gerektiriyor.
  const existing =
    unsignedIndex === -1
      ? []
      : (signerFields[unsignedIndex]?.children ?? []).map((node) => node.raw)
  const kept =
    unsignedIndex === -1
      ? signerFields.map((field) => field.raw)
      : signerFields.filter((_, index) => index !== unsignedIndex).map((field) => field.raw)

  const merged = derSetOf(...existing, ...attributes)
  const tagged = new Uint8Array(merged)
  tagged[0] = 0xa1

  const newSigner = wrapSequence([...kept, tagged])
  const newSignerInfos = wrapSet(signers.map((node, index) => (index === 0 ? newSigner : node.raw)))
  const newSignedData = wrapSequence(
    fields.map((field, index) => (index === signerInfosIndex ? newSignerInfos : field.raw)),
  )
  const newContent = wrapExplicit(0, newSignedData)
  return wrapSequence([contentInfo[0]?.raw ?? new Uint8Array(0), newContent])
}

/** `signerInfos` alanının konumu — yapının SON `SET`i. */
const findLastSetIndex = (fields: readonly DerNode[]): number => {
  for (let index = fields.length - 1; index >= 0; index -= 1) {
    const field = fields[index]
    if (field?.tagClass === 'universal' && field.tagNumber === 17) return index
  }
  return -1
}

/* Kodlanmış parçaları yeniden sarmak için küçük yardımcılar. Uzunluk
   yeniden hesaplandığı için `der.ts` yazıcıları kullanılıyor. */
const wrapSequence = (items: readonly Uint8Array[]): Uint8Array => encode(0x30, items)
const wrapSet = (items: readonly Uint8Array[]): Uint8Array => encode(0x31, items)
const wrapExplicit = (tagNumber: number, item: Uint8Array): Uint8Array =>
  encode(0xa0 | tagNumber, [item])

/** Verilen etiketle bir kurgusal değer kodlar. */
const encode = (tag: number, items: readonly Uint8Array[]): Uint8Array => {
  let length = 0
  for (const item of items) length += item.length
  const header: number[] = [tag]
  if (length < 0x80) {
    header.push(length)
  } else {
    const bytes: number[] = []
    let remaining = length
    while (remaining > 0) {
      bytes.unshift(remaining & 0xff)
      remaining = Math.floor(remaining / 256)
    }
    header.push(0x80 | bytes.length, ...bytes)
  }
  const out = new Uint8Array(header.length + length)
  out.set(header)
  let offset = header.length
  for (const item of items) {
    out.set(item, offset)
    offset += item.length
  }
  return out
}
