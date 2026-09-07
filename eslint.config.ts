import js from '@eslint/js'
import { defineConfig } from 'eslint/config'
import prettier from 'eslint-config-prettier'
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript'
import importX from 'eslint-plugin-import-x'
import tseslint from 'typescript-eslint'

/**
 * Katman düzeni — aşağıdan yukarı:
 *
 * ```
 *              sign / verify / upgrade        (tepe; her şeyi görür)
 *                    ┌─────┴─────┐
 *                  xades       cades         ← KARDEŞ
 *                    │           │
 *                    │      (XML görmez)
 *                    │           │
 *                  c14n         pki          ← KARDEŞ, birbirini göremez
 *                    │           │
 *                   xml        asn1
 *                    └─────┬─────┘
 *                        core                 (yaprak)
 * ```
 *
 * Kardeş izolasyonu bu pakette rastgele bir disiplin değil, doğrudan
 * doğrulanabilirlik kazandırır: `c14n` hiçbir kriptografi görmediği için
 * W3C'nin kendi test vektörleriyle tek başına sınanabilir, `pki` ise hiç
 * XML görmediği için PKCS#12 çözümü bir imza akışı kurmadan sınanabilir.
 * İki taraf yalnızca `xades` katmanında birleşir; bir hata çıktığında
 * hangi tarafta olduğu belirsiz kalmaz.
 */
const SIBLING_MESSAGE =
  'c14n/xml ile pki/asn1 kardeş katmanlardır ve birbirini import edemez; ' +
  'ikisini birleştirmek xades katmanının işidir.'

/** Bir katmanın import etmesi YASAK olan yolları üretir. */
const forbid = (
  patterns: readonly string[],
  message: string,
): {
  'no-restricted-imports': ['error', { patterns: { group: string[]; message: string }[] }]
} => ({
  'no-restricted-imports': [
    'error',
    { patterns: patterns.map((group) => ({ group: [group], message })) },
  ],
})

/**
 * Tepe katman modülleri — hiçbir alt katman bunlara bakamaz.
 *
 * Yol AÇIKÇA `../` ile yazılıyor. Yıldızlı geniş bir desen (iki yıldız,
 * eğik çizgi, `sign.js`) kardeş katmanların dosyalarını da yakalar ve
 * `cades/sign.js` gibi meşru bir bağımlılığı yanlışlıkla engeller.
 *
 * Not: o deseni buraya olduğu gibi yazmak mümkün değil — içindeki yıldız
 * ve eğik çizgi ikilisi blok yorumu erken kapatıyor.
 */
const TOP_LEVEL = ['../sign.js', '../verify.js', '../upgrade.js', '../index.js']

const ABOVE_CORE = ['**/asn1/**', '**/xml/**', '**/c14n/**', '**/pki/**', '**/xades/**']

export default defineConfig(
  { ignores: ['dist', 'coverage', 'node_modules', 'fixtures'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { 'import-x': importX },
    // `import-x/no-cycle` gerçek dosya yolunu çözebilen bir resolver OLMADAN
    // hiçbir şey rapor etmez: `.js` uzantılı bir TS import'unu (`./b.js` ->
    // `./b.ts`) haritalayamadığı için sessizce hiç ateşlenmez. Sessiz
    // etkisizlik, kapalı bir kuraldan daha tehlikelidir.
    settings: {
      'import-x/resolver-next': [createTypeScriptImportResolver()],
      'import-x/extensions': ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'],
    },
    rules: {
      'import-x/no-cycle': ['error', { maxDepth: Infinity }],
      'import-x/order': ['error', { 'newlines-between': 'always', alphabetize: { order: 'asc' } }],
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { ignoreRestSiblings: true }],
    },
  },
  // ── Katman: core ──────────────────────────────────────────────────────
  // Hata sınıfları ve bayt yardımcıları. Yaprak; hiçbir şeye bakamaz.
  {
    files: ['src/core/**/*.ts'],
    rules: forbid(ABOVE_CORE, 'core yaprak katmandır; hiçbir üst katmana bağımlı olamaz.'),
  },
  // ── Katman: asn1 ──────────────────────────────────────────────────────
  // DER okuyucu/yazıcı ve OID sözlüğü. XML'i bilmez.
  {
    files: ['src/asn1/**/*.ts'],
    rules: forbid(
      ['**/xml/**', '**/c14n/**', '**/pki/**', '**/xades/**'],
      `asn1 yalnızca core katmanına bağımlı olabilir. ${SIBLING_MESSAGE}`,
    ),
  },
  // ── Katman: xml ───────────────────────────────────────────────────────
  // İmza-sadık DOM, ayrıştırıcı ve serileştirici. Kriptografiyi bilmez.
  {
    files: ['src/xml/**/*.ts'],
    rules: forbid(
      ['**/asn1/**', '**/c14n/**', '**/pki/**', '**/xades/**'],
      `xml yalnızca core katmanına bağımlı olabilir. ${SIBLING_MESSAGE}`,
    ),
  },
  // ── Katman: c14n ──────────────────────────────────────────────────────
  // Kanonikleştirme. xml'in ÜSTÜNDE, pki'nin YANINDA.
  {
    files: ['src/c14n/**/*.ts'],
    rules: forbid(
      ['**/asn1/**', '**/pki/**', '**/xades/**'],
      `c14n yalnızca core ve xml katmanlarına bağımlı olabilir. ${SIBLING_MESSAGE}`,
    ),
  },
  // ── Katman: pki ───────────────────────────────────────────────────────
  // RC2, PBE, PKCS#12, X.509, CMS. asn1'in ÜSTÜNDE, c14n'in YANINDA.
  {
    files: ['src/pki/**/*.ts'],
    rules: forbid(
      ['**/xml/**', '**/c14n/**', '**/xades/**'],
      `pki yalnızca core ve asn1 katmanlarına bağımlı olabilir. ${SIBLING_MESSAGE}`,
    ),
  },
  // ── Katman: xades ─────────────────────────────────────────────────────
  // XML ile kriptonun birleştiği yer. Tepe katmanı ve cades görünmez.
  {
    files: ['src/xades/**/*.ts'],
    rules: forbid(
      [...TOP_LEVEL, '**/cades/**'],
      "xades katmanı tepe katmanına ya da kardeşi cades'e bağımlı olamaz.",
    ),
  },
  // ── Katman: cades ─────────────────────────────────────────────────────
  // İkili veri imzası. XML'i HİÇ görmez — kısıtlama değil, tanım.
  {
    files: ['src/cades/**/*.ts'],
    rules: forbid(
      ['**/xml/**', '**/c14n/**', '**/xades/**', '**/pdf/**', '**/pades/**', ...TOP_LEVEL],
      'cades yalnızca core, asn1 ve pki katmanlarına bağımlı olabilir; CAdES ikili veri imzasıdır ve XML de PDF de görmez.',
    ),
  },
  // ── Katman: pdf ───────────────────────────────────────────────────────
  // PDF yapısı. Kriptografiyi HİÇ görmez; xml katmanının PDF'teki eşi.
  {
    files: ['src/pdf/**/*.ts'],
    rules: forbid(
      [
        '**/asn1/**',
        '**/pki/**',
        '**/xml/**',
        '**/c14n/**',
        '**/xades/**',
        '**/cades/**',
        '**/pades/**',
        ...TOP_LEVEL,
      ],
      'pdf yalnızca core katmanına bağımlı olabilir; PDF yapısı kriptografi bilmez.',
    ),
  },
  // ── Katman: pades ─────────────────────────────────────────────────────
  // PDF ile CAdES'in birleştiği yer. Kendi kriptografisini getirmez.
  {
    files: ['src/pades/**/*.ts'],
    rules: forbid(
      ['**/xml/**', '**/c14n/**', '**/xades/**', ...TOP_LEVEL],
      'pades, pdf ve cades katmanlarının üstünde durur; XAdES tarafını görmez.',
    ),
  },
  // Testler daha gevşek: `!` orada bir iddia değil, "bu düzeneği ben kurdum,
  // burada olduğunu biliyorum" demenin en okunur yolu. Üretim kodunda ise
  // yasak kalır — orada bilinmeyen bir belge ayrıştırılıyor olabilir.
  {
    files: ['**/*.test.ts', 'tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
  prettier,
)
