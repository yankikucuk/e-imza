/**
 * CRC-32 (IEEE 802.3) — ZIP biçiminin şart koştuğu sağlama.
 *
 * Kriptografik bir özet DEĞİL ve öyle kullanılmamalı: amacı yalnızca ZIP
 * girdilerinin bütünlüğünü kabaca doğrulamak. İmzanın güvenliği buna
 * dayanmıyor; imza kapsanan baytların kendisi üzerinde hesaplanıyor.
 */

/** Yansıtılmış IEEE polinomu. */
const POLYNOMIAL = 0xedb88320

/** Tablo bir kez kurulur; her bayt için 8 tur döngü yerine tek arama. */
const TABLE = ((): Uint32Array => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i += 1) {
    let value = i
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1 ? (value >>> 1) ^ POLYNOMIAL : value >>> 1
    }
    table[i] = value >>> 0
  }
  return table
})()

/**
 * CRC-32 hesaplar.
 *
 * @param data - Girdi baytları
 * @returns 32 bitlik işaretsiz sağlama
 */
export const crc32 = (data: Uint8Array): number => {
  let crc = 0xffffffff
  for (const byte of data) {
    crc = (crc >>> 8) ^ (TABLE[(crc ^ byte) & 0xff] ?? 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}
