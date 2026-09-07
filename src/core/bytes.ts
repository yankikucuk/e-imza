/**
 * Bayt dizileriyle çalışan yardımcılar.
 *
 * İmza kodunun tamamı `Uint8Array` üzerinden konuşur, `Buffer` üzerinden
 * değil. `Buffer` bir Node ayrıcalığıdır; `Uint8Array` ise WebCrypto'nun,
 * tarayıcının ve `node:crypto`'nun ortak dilidir. Tek tip kullanmak, ileride
 * tarayıcı desteği eklenirse dönüşüm katmanı yazmayı gereksiz kılar.
 */

/**
 * Birden çok bayt dizisini tek bir diziye ekler.
 *
 * @param parts - Sırayla eklenecek diziler
 * @returns Tüm parçaların birleşimi
 */
export const concat = (...parts: readonly Uint8Array[]): Uint8Array => {
  let total = 0
  for (const part of parts) total += part.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/**
 * İki bayt dizisini **sabit zamanda** karşılaştırır.
 *
 * Karşılaştırma imza doğrulamada kullanılır ve orada erken çıkış bir yan
 * kanaldır: `a[0] !== b[0]` görünce dönen bir döngü, saldırgana doğru
 * baytları tek tek bulma imkânı verir. Uzunluk farkı gizlenemez (dizinin
 * boyutu zaten gözlenebilir), ama içerik farkının NEREDE olduğu gizlenir.
 *
 * @param a - Birinci dizi
 * @param b - İkinci dizi
 * @returns Diziler bayt bayt aynıysa `true`
 */
export const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  return diff === 0
}

/**
 * Bayt dizisini küçük harfli onaltılık gösterime çevirir.
 *
 * @param bytes - Kaynak diziler
 * @returns Onaltılık dize; her bayt iki karakter
 */
export const toHex = (bytes: Uint8Array): string => {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

/**
 * Onaltılık gösterimi bayt dizisine çevirir.
 *
 * @param hex - Boşluksuz, çift uzunlukta onaltılık dize (büyük/küçük harf farketmez)
 * @returns Çözülmüş baytlar
 * @throws {RangeError} Uzunluk tek ya da dizede onaltılık olmayan karakter varsa
 */
export const fromHex = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) {
    throw new RangeError(`Onaltılık dizenin uzunluğu çift olmalı: ${String(hex.length)} verildi.`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    const pair = hex.slice(i * 2, i * 2 + 2)
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) {
      throw new RangeError(`Onaltılık olmayan karakter: "${pair}"`)
    }
    out[i] = Number.parseInt(pair, 16)
  }
  return out
}

/** UTF-8 metni baytlara çevirir. */
export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)

/** UTF-8 baytları metne çevirir. */
export const fromUtf8 = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

/**
 * Bayt dizisini base64'e çevirir.
 *
 * @param bytes - Kaynak baytlar
 * @returns Satır sonu içermeyen base64 dizesi
 */
export const toBase64 = (bytes: Uint8Array): string =>
  Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64')

/**
 * base64 dizesini baytlara çevirir.
 *
 * Girdideki boşluk ve satır sonları yok sayılır: PEM ve XML içindeki base64
 * neredeyse her zaman satırlara bölünmüş gelir.
 *
 * @param text - base64 dizesi
 * @returns Çözülmüş baytlar
 */
export const fromBase64 = (text: string): Uint8Array => {
  const clean = text.replace(/\s+/g, '')
  return new Uint8Array(Buffer.from(clean, 'base64'))
}

/**
 * base64 dizesini sabit genişlikte satırlara böler.
 *
 * XMLDSig satır sonu istemez ama bazı doğrulayıcılar uzun tek satırdan
 * hoşlanmaz; `xadesjs#64` tam olarak bu yüzden açılmıştı (76 karakterlik
 * satırlar bekleyen bir doğrulayıcı). Varsayılan 64, PEM geleneğidir.
 *
 * @param base64 - Bölünecek dize
 * @param width - Satır genişliği; `0` ya da negatifse bölme yapılmaz
 * @returns `\n` ile ayrılmış satırlar
 */
export const wrapBase64 = (base64: string, width = 64): string => {
  if (width <= 0 || base64.length <= width) return base64
  const lines: string[] = []
  for (let i = 0; i < base64.length; i += width) lines.push(base64.slice(i, i + width))
  return lines.join('\n')
}
