import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/index.ts'],
      /**
       * Dal eşiği diğerlerinden belirgin biçimde düşük ve bu bilinçli.
       *
       * `tsconfig.json` içinde `noUncheckedIndexedAccess` açık: her dizi
       * erişimi `T | undefined` döner ve kod, tipi daraltmak için `?? 0`
       * yazmak zorunda kalır. Sınırları döngü koşuluyla garanti edilmiş bir
       * erişimde (`for (let i = 0; i < a.length; i += 1) … a[i] ?? 0`) o
       * `?? 0` dalı ÇALIŞMA ZAMANINDA ERİŞİLEMEZ, ama kapsam aracı onu
       * kapsanmamış sayar. RC2 ve RC4'ün iç döngülerinde bu yüzden onlarca
       * ölçülemez dal var.
       *
       * Eşiği yapay olarak yükseltmenin iki yolu vardı: her erişime kapsam
       * yönergesi serpmek ya da her baytı bir yardımcı fonksiyondan
       * geçirmek. Birincisi kodu okunmaz yapar, ikincisi blok şifresinin
       * iç döngüsüne çağrı maliyeti bindirir. Üçüncü yol — eşiği gerçeğe
       * göre ayarlayıp nedenini yazmak — dürüst olanı.
       *
       * Satır, ifade ve fonksiyon eşikleri yüksek tutuldu; asıl güvence
       * onlarda.
       */
      thresholds: { lines: 93, branches: 75, functions: 95, statements: 90 },
    },
  },
})
