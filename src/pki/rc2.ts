import { timingSafeEqual } from '../core/bytes.js'

/**
 * RC2 blok şifresi (RFC 2268) — yalnızca eski PKCS#12 kaplarını açmak için.
 *
 * ## Neden saf JavaScript?
 *
 * Node'un OpenSSL 3'ünde RC2 varsayılan sağlayıcıdan çıkarıldı;
 * `crypto.createDecipheriv('rc2-40-cbc', …)` "digital envelope routines::
 * unsupported" hatası verir. WebCrypto'da RC2 hiç yoktur. Sonuç: `pkijs`
 * temelli her kütüphane — `tr-esign` dâhil — bu dosyaları açamaz.
 *
 * Bu önemlidir çünkü Türkiye'de mali mühür ve NES sertifikaları sıklıkla
 * eski Java ya da Windows araçlarıyla dışa aktarılır ve o araçlar sertifika
 * bölümünü `pbeWithSHAAnd40BitRC2-CBC` ile şifreler. Kullanıcı açısından
 * fark şudur: dosya ya açılır ya açılmaz.
 *
 * ## Güvenlik notu
 *
 * RC2 kırılmış sayılır ve bu kütüphane onunla **hiçbir şey şifrelemez** —
 * yalnızca çözer. Şifreleme yönü bilinçli olarak yoktur: yeni bir dosyayı
 * RC2 ile yazmak, kullanıcının anahtarını zayıf bir kabın içine koymak
 * olurdu. Blok şifreleme fonksiyonu yine de gerekli, çünkü RC2'nin çözme
 * yönü ancak şifreleme yönüyle birlikte doğrulanabilir.
 */

/** RFC 2268 §2 `PITABLE` — anahtar genişletmede kullanılan sabit ikame tablosu. */
const PITABLE = new Uint8Array([
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
])

/** 16 bitlik sola döndürme. */
const rotl16 = (value: number, bits: number): number =>
  ((value << bits) | (value >>> (16 - bits))) & 0xffff

/** 16 bitlik sağa döndürme. */
const rotr16 = (value: number, bits: number): number =>
  ((value >>> bits) | (value << (16 - bits))) & 0xffff

/**
 * RC2 anahtar genişletme (RFC 2268 §2).
 *
 * @param key - Ham anahtar baytları (1–128)
 * @param effectiveBits - Etkin anahtar uzunluğu (bit); PKCS#12'de 40 ya da 128
 * @returns 64 adet 16 bitlik yuvarlak anahtarı
 */
export const expandRc2Key = (key: Uint8Array, effectiveBits: number): Uint16Array => {
  if (key.length < 1 || key.length > 128) {
    throw new RangeError(`RC2 anahtarı 1–128 bayt olmalı: ${String(key.length)} verildi.`)
  }
  if (effectiveBits < 1 || effectiveBits > 1024) {
    throw new RangeError(`RC2 etkin anahtar uzunluğu 1–1024 bit olmalı: ${String(effectiveBits)}`)
  }

  const L = new Uint8Array(128)
  L.set(key)
  const T = key.length
  for (let i = T; i < 128; i += 1) {
    L[i] = PITABLE[((L[i - 1] ?? 0) + (L[i - T] ?? 0)) & 0xff] ?? 0
  }

  const T8 = Math.ceil(effectiveBits / 8)
  // TM, son (kısmi) baytta kaç bitin anlamlı olduğunu maskeler.
  const TM = 255 % Math.pow(2, 8 + effectiveBits - 8 * T8)
  L[128 - T8] = PITABLE[(L[128 - T8] ?? 0) & TM] ?? 0
  for (let i = 127 - T8; i >= 0; i -= 1) {
    L[i] = PITABLE[(L[i + 1] ?? 0) ^ (L[i + T8] ?? 0)] ?? 0
  }

  const K = new Uint16Array(64)
  for (let i = 0; i < 64; i += 1) K[i] = (L[2 * i] ?? 0) | ((L[2 * i + 1] ?? 0) << 8)
  return K
}

/** Döndürme miktarları — karıştırma turunda her söz için sabittir. */
const SHIFTS = [1, 2, 3, 5] as const

/**
 * Tek bir 8 baytlık bloğu şifreler.
 *
 * Bu yön PKCS#12 okumak için gerekmez; çözme yönünün doğruluğunu
 * kanıtlayabilmek için vardır (RFC 2268 test vektörleri şifreleme
 * yönündedir).
 *
 * @param block - 8 baytlık düz metin
 * @param roundKeys - {@link expandRc2Key} çıktısı
 * @returns 8 baytlık şifreli metin
 */
export const rc2EncryptBlock = (block: Uint8Array, roundKeys: Uint16Array): Uint8Array => {
  const R = readWords(block)
  let j = 0
  const mix = (): void => {
    for (let i = 0; i < 4; i += 1) {
      const a = R[(i + 3) % 4] ?? 0
      const b = R[(i + 2) % 4] ?? 0
      const c = R[(i + 1) % 4] ?? 0
      R[i] = ((R[i] ?? 0) + (roundKeys[j] ?? 0) + (a & b) + (~a & c)) & 0xffff
      j += 1
      R[i] = rotl16(R[i] ?? 0, SHIFTS[i] ?? 1)
    }
  }
  const mash = (): void => {
    for (let i = 0; i < 4; i += 1) {
      R[i] = ((R[i] ?? 0) + (roundKeys[(R[(i + 3) % 4] ?? 0) & 63] ?? 0)) & 0xffff
    }
  }
  for (let round = 0; round < 5; round += 1) mix()
  mash()
  for (let round = 0; round < 6; round += 1) mix()
  mash()
  for (let round = 0; round < 5; round += 1) mix()
  return writeWords(R)
}

/**
 * Tek bir 8 baytlık bloğu çözer.
 *
 * @param block - 8 baytlık şifreli metin
 * @param roundKeys - {@link expandRc2Key} çıktısı
 * @returns 8 baytlık düz metin
 */
export const rc2DecryptBlock = (block: Uint8Array, roundKeys: Uint16Array): Uint8Array => {
  const R = readWords(block)
  let j = 63
  const unmix = (): void => {
    for (let i = 3; i >= 0; i -= 1) {
      R[i] = rotr16(R[i] ?? 0, SHIFTS[i] ?? 1)
      const a = R[(i + 3) % 4] ?? 0
      const b = R[(i + 2) % 4] ?? 0
      const c = R[(i + 1) % 4] ?? 0
      R[i] = ((R[i] ?? 0) - (roundKeys[j] ?? 0) - (a & b) - (~a & c)) & 0xffff
      j -= 1
    }
  }
  const unmash = (): void => {
    for (let i = 3; i >= 0; i -= 1) {
      R[i] = ((R[i] ?? 0) - (roundKeys[(R[(i + 3) % 4] ?? 0) & 63] ?? 0)) & 0xffff
    }
  }
  for (let round = 0; round < 5; round += 1) unmix()
  unmash()
  for (let round = 0; round < 6; round += 1) unmix()
  unmash()
  for (let round = 0; round < 5; round += 1) unmix()
  return writeWords(R)
}

/** 8 baytı dört adet küçük-endian 16 bitlik söze çevirir. */
const readWords = (block: Uint8Array): Uint16Array => {
  if (block.length !== 8) {
    throw new RangeError(`RC2 blok boyutu 8 bayt olmalı: ${String(block.length)} verildi.`)
  }
  const R = new Uint16Array(4)
  for (let i = 0; i < 4; i += 1) R[i] = (block[2 * i] ?? 0) | ((block[2 * i + 1] ?? 0) << 8)
  return R
}

/** Dört sözü 8 bayta çevirir. */
const writeWords = (R: Uint16Array): Uint8Array => {
  const out = new Uint8Array(8)
  for (let i = 0; i < 4; i += 1) {
    out[2 * i] = (R[i] ?? 0) & 0xff
    out[2 * i + 1] = ((R[i] ?? 0) >> 8) & 0xff
  }
  return out
}

/**
 * RC2-CBC ile çözer ve PKCS#7 dolgusunu kaldırır.
 *
 * @param ciphertext - Şifreli veri; uzunluğu 8'in katı olmalı
 * @param key - Ham anahtar
 * @param iv - 8 baytlık başlangıç vektörü
 * @param effectiveBits - Etkin anahtar uzunluğu (bit)
 * @returns Dolgusu kaldırılmış düz metin
 * @throws {RangeError} Uzunluklar tutmuyorsa ya da dolgu geçersizse
 */
export const rc2CbcDecrypt = (
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  effectiveBits: number,
): Uint8Array => {
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new RangeError(`RC2-CBC girdisi 8'in katı olmalı: ${String(ciphertext.length)} bayt.`)
  }
  if (iv.length !== 8) {
    throw new RangeError(`RC2-CBC başlangıç vektörü 8 bayt olmalı: ${String(iv.length)} verildi.`)
  }

  const roundKeys = expandRc2Key(key, effectiveBits)
  const out = new Uint8Array(ciphertext.length)
  let previous = iv
  for (let offset = 0; offset < ciphertext.length; offset += 8) {
    const block = ciphertext.subarray(offset, offset + 8)
    const plain = rc2DecryptBlock(block, roundKeys)
    for (let i = 0; i < 8; i += 1) out[offset + i] = (plain[i] ?? 0) ^ (previous[i] ?? 0)
    previous = block
  }
  return stripPkcs7Padding(out)
}

/**
 * PKCS#7 dolgusunu kaldırır.
 *
 * Dolgu doğrulaması **sabit zamanda** yapılır. Erken çıkan bir doğrulama
 * klasik bir dolgu kâhini (padding oracle) açar: saldırgan yanlış şifreyle
 * yapılan denemelerin ne kadar sürdüğüne bakarak düz metni bayt bayt
 * çıkarabilir.
 *
 * @param data - Dolgulu düz metin
 * @returns Dolgusuz veri
 */
const stripPkcs7Padding = (data: Uint8Array): Uint8Array => {
  const padding = data[data.length - 1] ?? 0
  if (padding < 1 || padding > 8 || padding > data.length) {
    throw new RangeError('Geçersiz PKCS#7 dolgusu — büyük olasılıkla şifre yanlış.')
  }
  const expected = new Uint8Array(padding).fill(padding)
  if (!timingSafeEqual(data.subarray(data.length - padding), expected)) {
    throw new RangeError('Geçersiz PKCS#7 dolgusu — büyük olasılıkla şifre yanlış.')
  }
  return data.subarray(0, data.length - padding)
}
