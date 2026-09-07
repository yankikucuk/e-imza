/**
 * RC4 akış şifresi — yalnızca eski PKCS#12 kaplarını açmak için.
 *
 * {@link ./rc2.js | RC2} ile aynı gerekçe: Node'un OpenSSL 3'ünde RC4 de
 * varsayılan sağlayıcıdan çıkarıldı ve WebCrypto'da hiç yok. `pbeWithSHAAnd
 * 128BitRC4` ile yazılmış bir kap, saf JS uygulaması olmadan Node'da
 * açılamaz.
 *
 * RC4 kırılmıştır ve bu kütüphane onunla hiçbir şey şifrelemez. Akış şifresi
 * olduğu için tek bir fonksiyon hem şifreler hem çözer — ayrı bir "şifrele"
 * yönü yazmamak, yanlışlıkla kullanılmasını da engeller.
 */

/**
 * RC4 anahtar akışını veriyle XOR'lar.
 *
 * Akış şifrelerinde şifreleme ile çözme aynı işlemdir; fonksiyon her iki
 * yönde de kullanılır. Dolgu yoktur, uzunluk korunur.
 *
 * @param data - Şifrelenecek ya da çözülecek veri
 * @param key - Ham anahtar (1–256 bayt)
 * @returns Aynı uzunlukta sonuç
 * @throws {RangeError} Anahtar uzunluğu aralık dışıysa
 */
export const rc4 = (data: Uint8Array, key: Uint8Array): Uint8Array => {
  if (key.length < 1 || key.length > 256) {
    throw new RangeError(`RC4 anahtarı 1–256 bayt olmalı: ${String(key.length)} verildi.`)
  }

  // Anahtar planlama (KSA).
  const S = new Uint8Array(256)
  for (let i = 0; i < 256; i += 1) S[i] = i
  let j = 0
  for (let i = 0; i < 256; i += 1) {
    j = (j + (S[i] ?? 0) + (key[i % key.length] ?? 0)) & 0xff
    const swap = S[i] ?? 0
    S[i] = S[j] ?? 0
    S[j] = swap
  }

  // Sözde rastgele üretim (PRGA).
  const out = new Uint8Array(data.length)
  let x = 0
  let y = 0
  for (let n = 0; n < data.length; n += 1) {
    x = (x + 1) & 0xff
    y = (y + (S[x] ?? 0)) & 0xff
    const swap = S[x] ?? 0
    S[x] = S[y] ?? 0
    S[y] = swap
    out[n] = (data[n] ?? 0) ^ (S[((S[x] ?? 0) + (S[y] ?? 0)) & 0xff] ?? 0)
  }
  return out
}
