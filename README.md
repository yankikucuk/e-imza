# @yankikucuk/e-imza

> **Durum: 1.2.0 — kararlı.** XAdES'in **beş seviyesi de** hazır:
> BES, EPES, T, LT, LTA. Yanında RFC 3161 zaman damgası, RFC 6960 OCSP,
> CMS okuma, kanonikleştirme, PKCS#12 kap okuma, ayrık imzalama ve paralel
> imza. Public API kararlıdır; kırıcı değişiklik ana sürüm yükseltir.
> CAdES, PAdES ve ASiC yol haritasında ve katkısal.

Elektronik imza için sıfır bağımlılıklı bir TypeScript kütüphanesi.
UBL-TR e-Fatura ve e-İrsaliye belgelerini mali mühürle imzalar, imzalı
belgeleri doğrular.

Çalışma zamanı bağımlılığı **yoktur**. Gereken her şey — kanonikleştirme,
ASN.1, PKCS#12, hatta artık Node'un kriptografisinde bulunmayan RC2 ve
RC4 — paketin içindedir.

## Neden

Bu paketi yazmadan önce mevcut JavaScript uygulamaları ölçüldü. Üç
somut bulgu çıktı ve üçü de kalıcı testlere bağlandı.

### 1. UBL uzantısındaki imza xadesjs ile doğrulanamıyor

GİB, e-Fatura imzasını `ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent`
içine bekler. `xadesjs`'in `enveloped-signature` dönüşümü ise yalnızca imza
kök öğenin **doğrudan çocuğuyken** çalışıyor; daha derine gömülünce dönüşüm
sessizce hiçbir şey yapmıyor ve özete imzanın kendisi de giriyor.

Hangi tarafın haklı olduğuna libxml2 karar veriyor:

|                                                | özet                   |
| ---------------------------------------------- | ---------------------- |
| imza çıkarıldıktan sonra kalan belge (libxml2) | `wXIZvLWEe1Qf9haSO…`   |
| **bu paketin imzada beyan ettiği**             | `wXIZvLWEe1Qf9haSO…` ✓ |
| xadesjs'in hesapladığı                         | `gZLVNoBe0pS3Dw4LQ…` ✗ |

`xadesjs#73`, Kasım 2018'de açıldı, hâlâ açık, 2.6.8'de yeniden
üretiliyor. Ölçüm `tests/xadesjs-interop.test.ts` içinde sabitlendi.

### 2. Eski `.p12` dosyaları pkijs ile açılamıyor

Eski Java ve Windows araçları — ve macOS'un sistem LibreSSL'i — PKCS#12
kabının sertifika bölümünü `pbeWithSHAAnd40BitRC2-CBC` ile şifreler. RC2,
Node'un OpenSSL 3'ünde varsayılan sağlayıcıdan çıkarıldı ve WebCrypto'da
hiç yok:

|                        | eski (RC2-40)                                                     | modern (PBES2/AES-256) |
| ---------------------- | ----------------------------------------------------------------- | ---------------------- |
| pkijs 3                | ✗ `Unknown "contentEncryptionAlgorithm": 1.2.840.113549.1.12.1.6` | ✓                      |
| **@yankikucuk/e-imza** | ✓                                                                 | ✓                      |

RC2 ve RC4 bu pakette saf JavaScript olarak var; RFC 2268'in sekiz test
vektörüyle iki yönde ve LibreSSL'in ürettiği şifreli metinlerle
doğrulanıyor. Yalnızca **çözme** yönü dışa açık: yeni bir kabı zayıf bir
şifreyle yazmanın gerekçesi yok.

### 3. Özel anahtara erişilemediğinde imzalamanın yolu yoktu

Mali mühür bir donanım modülünde, NES bir akıllı kartta olabilir. O zaman
kütüphaneye "anahtarı al, imzala" denemez; "şu baytları imzala ve sonucu
getir" denmesi gerekir. `xadesjs#85`, `#133`, `node-signpdf#270` ve `#272`
hep bunu istiyordu. Bu pakette `prepare()` / `complete()` ayrımı bu iş için
var — üstelik kartların istediği üç biçimi de veriyor.

## Kurulum

```bash
npm install @yankikucuk/e-imza
```

Node 20 veya üstü.

## Hızlı başlangıç

```ts
import { loadPkcs12, sign, verify } from '@yankikucuk/e-imza'
import { readFileSync } from 'node:fs'

// Mali mühür kabını aç. Parolayı koda gömmeyin.
const { privateKey, certificate, chain } = loadPkcs12(
  new Uint8Array(readFileSync('mali-muhur.p12')),
  process.env.MUHUR_SIFRESI ?? '',
)

// e-Fatura'yı imzala. İmza ext:ExtensionContent içine yerleşir.
const imzali = sign({
  xml: faturaXml,
  signer: { certificate, chain },
  privateKey,
  commitmentType: 'proof-of-origin',
  productionPlace: { city: 'İstanbul', country: 'TR' },
})

// Doğrula.
const sonuc = verify(imzali)
if (sonuc.valid) {
  console.log(sonuc.level) // 'BES'
  console.log(sonuc.signer.subjectName) // 'CN=…,O=…,C=TR'
  console.log(sonuc.signer.subjectSerialNumber) // VKN
}
```

`@yankikucuk/ubl-tr` ile birlikte kullanıldığında fatura üretimi ve
imzalama uçtan uca tamamlanır; iki paket birbirini import etmez, imza
katmanı belge katmanını bilmez.

## `@yankikucuk/ubl-tr` ile birlikte

İki paket birbirini **import etmez**. Bu bilinçli: imza katmanı belge
katmanını bilmemeli, belge katmanı da imza katmanını. Aralarındaki bağ tek
bir yapısal sözleşme — UBL-TR belgesindeki boş `ext:ExtensionContent`.
`ubl-tr` onu boş bırakır, `e-imza` doldurur.

Sonuç: `ubl-tr` kullanmayanlar `e-imza`'yı kendi XML'leriyle kullanabilir,
`e-imza` kullanmayanlar `ubl-tr` faturasını başka bir araçla imzalayabilir.

```bash
npm install @yankikucuk/ubl-tr @yankikucuk/e-imza
```

### Uçtan uca: üret → imzala → doğrula → oku

```ts
import {
  buildInvoiceXml,
  InvoiceProfile,
  InvoiceType,
  parseDocument,
  parseInvoice,
  validateInvoiceRules,
} from '@yankikucuk/ubl-tr'
import { loadPkcs12, sign, verify } from '@yankikucuk/e-imza'
import { readFileSync } from 'node:fs'

// ── 1. Belge: ubl-tr üretir ───────────────────────────────────────────
// Toplamları kütüphane hesaplar; imza zarfı (boş ext:ExtensionContent)
// varsayılan olarak yazılır.
const fatura = buildInvoiceXml({
  id: 'ABC2026000000001',
  uuid: '1a2b3c4d-0001-4000-8001-000000000001',
  issueDate: '2026-09-07',
  profile: InvoiceProfile.TEMEL,
  type: InvoiceType.SATIS,
  supplier: {
    taxNumber: '1234567890',
    name: 'ÖRNEK SATICI A.Ş.',
    taxOffice: 'Kadıköy',
    address: { district: 'Kadıköy', city: 'İstanbul' },
  },
  customer: {
    taxNumber: '9876543210',
    name: 'Örnek Alıcı Ltd. Şti.',
    address: { district: 'Çankaya', city: 'Ankara' },
  },
  lines: [{ name: 'Danışmanlık hizmeti', quantity: 10, unitPrice: 100, vatRate: 20 }],
})

// ── 2. İmza: e-imza mali mühürle imzalar ──────────────────────────────
const { privateKey, certificate, chain } = loadPkcs12(
  new Uint8Array(readFileSync('mali-muhur.p12')),
  process.env.MUHUR_SIFRESI ?? '',
)

const imzali = sign({
  xml: fatura,
  signer: { certificate, chain },
  privateKey,
  commitmentType: 'proof-of-origin',
  productionPlace: { city: 'İstanbul', country: 'TR' },
})

// ── 3. Doğrulama ──────────────────────────────────────────────────────
const imza = verify(imzali)
if (!imza.valid) throw new Error(`İmza geçersiz: ${imza.reason}`)

// İmzalayanın beklediğiniz mükellef olduğunu ayrıca doğrulayın.
// Türk sertifikalarında VKN/TCKN konudaki serialNumber alanında taşınır.
if (imza.signer.subjectSerialNumber !== '1234567890') {
  throw new Error('İmza başka bir mükellefe ait')
}

// ── 4. Okuma: ubl-tr imzalı belgeyi hâlâ okur ─────────────────────────
// İmza belgeyi bozmaz; ubl-tr onu ayrıştırır ve iş kurallarını denetler.
const { root } = parseDocument(imzali)
const okunan = parseInvoice(root)
const kurallar = validateInvoiceRules(root)

console.log(okunan.id) // 'ABC2026000000001'
console.log(okunan.supplier?.name) // 'ÖRNEK SATICI A.Ş.'
console.log(kurallar.valid) // true
```

> `parseInvoice` ve `validateInvoiceRules` **XML dizesi değil, ayrıştırılmış
> kök öğe** alır — önce `parseDocument` çağırın. Doğrudan dize verirseniz
> TypeScript uyarır, ama düz JavaScript'te sessizce boş sonuç dönersiniz.

### Neden ayrı paketler

|                      | `@yankikucuk/ubl-tr`               | `@yankikucuk/e-imza`                  |
| -------------------- | ---------------------------------- | ------------------------------------- |
| Sorumluluk           | belge üretimi, okuma, iş kuralları | kanonikleştirme, imza, doğrulama      |
| Bilmediği            | XAdES, sertifika, kanonik biçim    | UBL, KDV, tevkifat, fatura profilleri |
| Bağımlılık           | sıfır                              | sıfır                                 |
| Birbirine bağımlılık | **yok**                            | **yok**                               |

İmzasız kullanım da anlamlıdır: e-Arşiv portal akışında belge GİB tarafında
imzalanır, siz yalnızca üretirsiniz. İmzayı ayrı tutmak o senaryoyu
zorunlu bir bağımlılıkla ağırlaştırmıyor.

### Sırayı bozmayın

İmza belgenin **son** adımıdır. İmzaladıktan sonra XML'e dokunmak — bir
boşluk eklemek bile — imzayı geçersiz kılar; kanonikleştirme boşluğu
"temizlemez", çünkü temizleseydi imza kapsamı belirsizleşirdi.

```ts
const imzali = sign({ xml: fatura, signer, privateKey })
const bozuk = imzali.replace('118.00', '119.00')

verify(bozuk).valid // false — tek bir rakam yetti
```

### e-İrsaliye

Aynı akış `buildDespatchAdviceXml` ile de çalışır; e-İrsaliye de aynı
`ext:UBLExtensions` yapısını taşır ve `placement` varsayılanı değişmez.

```ts
import { buildDespatchAdviceXml } from '@yankikucuk/ubl-tr'

const imzali = sign({
  xml: buildDespatchAdviceXml(irsaliye),
  signer: { certificate, chain },
  privateKey,
})
```

## Akıllı kart, HSM ve uzak imza

Özel anahtar sürece hiç girmez:

```ts
import { prepare, complete } from '@yankikucuk/e-imza'

const bekleyen = prepare({
  xml: faturaXml,
  signer: { certificate }, // yalnızca sertifika; anahtar yok
})

// Karta/HSM'e ne vereceğiniz kullandığınız mekanizmaya bağlı:
//
//   CKM_SHA256_RSA_PKCS  → bekleyen.dataToSign   (kart kendi özetler)
//   CKM_RSA_PKCS         → bekleyen.digestInfo   (DER DigestInfo)
//   CKM_ECDSA            → bekleyen.digest       (ham özet)
//
const imza = await kart.imzala(bekleyen.digestInfo ?? bekleyen.dataToSign)

const imzali = complete(bekleyen, imza)
```

`digestInfo` alanı EC anahtarlarda `undefined` olur. ECDSA imzası **ham
`r‖s`** biçiminde beklenir, ASN.1 DER değil — XMLDSig bunu şart koşar.

## Paralel imza

Aynı belgeyi birden çok kişinin bağımsız imzalaması. Varsayılan davranış
bunu **desteklemez** ve bu doğrudur: `enveloped-signature` dönüşümü tanımı
gereği yalnızca kendi imzasını kapsam dışında bırakır, dolayısıyla ikinci
imza eklendiğinde birincinin kapsadığı içerik değişir ve birinci imza
geçersiz olur.

`parallel: true` verildiğinde XPath Filter 2.0 ile **bütün** imzalar kapsam
dışında bırakılır; imzacılar aynı içeriği imzalar ve imzalar birbirinden
bağımsız olur:

```ts
const birinci = sign({ xml, signer: a, privateKey: ka, parallel: true })
const ikinci = sign({ xml: birinci, signer: b, privateKey: kb, parallel: true })

verifyAll(ikinci).every((sonuc) => sonuc.valid) // true
```

UBL-TR e-Fatura tek imza bekler; orada varsayılan doğrudur.

## Zaman damgası (XAdES-T)

Zaman damgası, imzanın **belirli bir andan önce atıldığını** üçüncü bir
tarafa kanıtlatır. Sertifikanız sonradan iptal edilse ya da süresi dolsa
bile damga, o ana kadar geçerli olduğunu gösterir.

Kütüphane TSA'ya **bağlanmaz**. İstek baytlarını üretir, jetonu yerleştirir;
aradaki HTTP çağrısı sizin. Bir imza kütüphanesinin ne zaman ve nereye
bağlandığı çağıranın kararı olmalı — hem güvenlik açısından, hem de bu
akış çoğu zaman kuyruk ve yeniden deneme mantığı gerektirdiği için.

```ts
import { timestampRequest, upgrade, parseTimestampResponse, verify } from '@yankikucuk/e-imza'

// 1. İsteği üret. Damgalanan şey, kanonikleştirilmiş ds:SignatureValue ÖĞESİDİR.
const istek = timestampRequest({ xml: imzali })

// 2. TSA'ya gönder — Kamu SM: http://tzd.kamusm.gov.tr
const yanit = await fetch('http://tzd.kamusm.gov.tr', {
  method: 'POST',
  headers: { 'content-type': 'application/timestamp-query' },
  body: istek,
})
const jeton = parseTimestampResponse(new Uint8Array(await yanit.arrayBuffer()))

// 3. Yerleştir. Jetonun BU imzayı damgaladığı doğrulanır; tutmuyorsa hata verir.
const damgali = upgrade({ xml: imzali, to: 'T', token: jeton })

verify(damgali).level // 'T'
```

### Yükseltme imzayı neden bozmuyor

Damga `xades:UnsignedProperties` altına yazılır ve o alt ağaç **hiçbir
`ds:Reference` tarafından kapsanmaz**. Adı da bunu söylüyor: imzalanmamış
özellikler. `SignedProperties`e bir şey eklemek imzayı anında geçersiz
kılardı.

Aynı imzaya birden çok damga eklenebilir; hepsi aynı `ds:SignatureValue`yu
damgalar ve `verify()` her birini ayrı raporlar.

### Seviye, iddiaya değil kanıta bakar

`verify()` bulduğu her damgayı gerçekten doğrular: jeton kriptografik
olarak geçerli mi, ve **bu** imzayı mı damgalıyor. Doğrulanmayan bir damga
seviyeyi yükseltmez.

```ts
const sonuc = verify(supheliBelge)
sonuc.level // 'BES' — belge <xades:SignatureTimeStamp> içerse bile
sonuc.timestamps[0].valid // false
sonuc.timestamps[0].reason // 'Jeton başka bir veriyi damgalamış — özet eşleşmiyor.'
sonuc.warnings // [{ code: 'timestamp-invalid', … }]
```

Yapıya bakıp "T" demek damganın var oluş amacını ortadan kaldırırdı:
`<xades:SignatureTimeStamp>` etiketini belgeye herkes yazabilir.

### RFC 3161 katmanı ayrıca kullanılabilir

Protokol XAdES'ten bağımsız olarak da çalışır — herhangi bir veriyi
damgalamak ve doğrulamak için:

```ts
import { buildTimestampRequest, verifyTimestampToken } from '@yankikucuk/e-imza'

const istek = buildTimestampRequest({ messageImprint: ozet, nonce: rastgele })
// … TSA'ya gönder …
const sonuc = verifyTimestampToken(jeton, { data: veri, nonce: rastgele })
sonuc.valid && sonuc.info.genTime
```

`data` vermezseniz jeton kriptografik olarak doğrulanır ama **neyi
damgaladığı bilinmez**; `nonce` vermezseniz yanıt tekrar oynatmaya açık
kalır. İkisi de isteğe bağlı, ama ikisini birden atlamak damgayı büyük
ölçüde anlamsızlaştırır.

## Uzun dönem: LT ve LTA

Zaman damgası imzanın **ne zaman** atıldığını kanıtlar; LT ve LTA imzanın
**yıllar sonra da doğrulanabilir** kalmasını sağlar.

Sorun şu: bugün geçerli olan sertifikanın beş yıl sonra süresi dolmuş
olacak ve "imza atıldığı anda bu sertifika iptal edilmiş miydi?" sorusunun
cevabı hiçbir yerde bulunamayacak — OCSP yanıtlayıcıları geçmişi saklamaz.
**LT** o cevabı imzanın içine gömer. **LTA** ise gömülen kanıtın da üstüne
bir arşiv damgası atar, çünkü OCSP yanıtını imzalayan sertifikanın da bir
gün süresi dolar.

### LT — zincir ve iptal kanıtı

```ts
import {
  buildOcspRequest,
  ocspResponderUrls,
  parseOcspResponse,
  upgrade,
  verifyOcspResponse,
} from '@yankikucuk/e-imza'

// 1. İptal kanıtını al. Yanıtlayıcının adresi sertifikanın içinde yazılı.
const [adres] = ocspResponderUrls(certificate)
const istek = buildOcspRequest({ certificate, issuer: araCa, nonce })
const ham = await fetch(adres!, {
  method: 'POST',
  headers: { 'content-type': 'application/ocsp-request' },
  body: istek,
})
const yanit = parseOcspResponse(new Uint8Array(await ham.arrayBuffer()))

// 2. Gömmeden ÖNCE doğrula: yanıt gerçekten bu sertifikaya mı ait?
const durum = verifyOcspResponse(yanit, { certificate, issuer: araCa, nonce })
if (!durum.valid) throw new Error(durum.reason)
if (durum.certificateStatus.status !== 'good') throw new Error('Sertifika iptal edilmiş')

// 3. Zinciri ve kanıtı imzaya göm.
const lt = upgrade({
  xml: damgali,
  to: 'LT',
  certificates: [araCa, kokCa],
  ocspResponses: [yanit.der],
})

verify(lt).level // 'LT'
```

Yalnızca zincir gömmek LT sayılmaz: iptal kanıtı olmadan imza yine
doğrulanamaz. `upgrade()` bu yüzden en az bir OCSP yanıtı ya da CRL ister
ve yoksa açık hata verir — sessizce kabul etmek, kullanıcıya sahte bir
uzun-dönem güvencesi vermek olurdu.

### LTA — arşiv damgası

```ts
import { archiveTimestampRequest, upgrade } from '@yankikucuk/e-imza'

const istek = archiveTimestampRequest({ xml: lt })
// … TSA'ya gönder, jetonu al …
const lta = upgrade({ xml: lt, to: 'LTA', token: jeton })

verify(lta).level // 'LTA'
```

Arşiv damgası imzanın **ve o ana kadarki bütün imzalanmamış özelliklerin**
tamamını kapsar — LT verisi dâhil. Gömülen OCSP yanıtının tek bir baytı
değişse arşiv damgası tutmaz. Damga periyodik olarak yenilenebilir; her
yeni damga bir öncekini de kapsar.

`verify()` her damgayı ayrı raporlar:

```ts
const sonuc = verify(lta)
sonuc.timestamps.map((d) => [d.kind, d.valid])
// [['signature', true], ['archive', true]]
```

### Hangi tanım — ve sınırı

Arşiv damgasının girdi hesabı **ETSI TS 101 903 v1.4.2 §8.2.1** uyarınca
yapılıyor. EN 319 132 farklı bir girdi tanımlar; ikisi uyumlu değildir ve
bu paket TS 101 903'ü uygular.

Dürüst olmak gerekirse: zaman damgasının **kendisi** OpenSSL ile iki yönde
sınandı, ama arşiv damgasının **girdi hesabı** bağımsız bir uygulamayla
çapraz doğrulanamadı. Riski karşılamak için girdinin bileşimi doğrudan
teste bağlandı — hangi parçaların hangi sırayla girdiğini sabitleyen ayrı
bir iddia var. Yine de, LTA imzalarınızı üretime almadan önce karşı tarafın
doğrulayıcısıyla denemenizi öneririm.

## Kanonikleştirme

Kanonikleştirici ayrıca kullanılabilir. **Canonical XML 1.0** ve
**Exclusive C14N**, yorumlu ve yorumsuz dört varyantla:

```ts
import { canonicalize, parseXml } from '@yankikucuk/e-imza'

canonicalize(parseXml(xml), { algorithm: 'exc-c14n' })

// Belgenin ortasındaki bir alt ağaç — ata bağlamı belgeden okunur.
canonicalize(doc, { algorithm: 'c14n10', subset: hedefOge })

// Bir alt ağacı çıkararak (enveloped-signature dönüşümünün anlamı).
canonicalize(doc, { algorithm: 'exc-c14n', omit: new Set([imzaOgesi]) })
```

Doğrulaması iki bağımsız kaynağa dayanıyor:

- **W3C `REC-xml-c14n-20010315` §3.1–3.6 uygunluk vektörleri.** Beklenen
  çıktılar spesifikasyondan birebir alındı. `xadesjs#12` bu testleri
  2016'dan beri istiyordu.
- **libxml2 ile fark testi.** Dokuz belge, iki algoritma, bayt bayt aynı
  sonuç. Kendi testlerimiz kendi yorumumuzu paylaşabilir; libxml2
  paylaşmaz.

Alt küme kanonikleştirmesinde — yani imza yolunda — ölçülen durum
(Eylül 2026):

|                            | tam belge | alt küme              |
| -------------------------- | --------- | --------------------- |
| xmldsigjs 2.8.8, kapsayıcı | ✓ 8/8     | **✗ 4'te 3'ü yanlış** |
| xmldsigjs 2.8.8, dışlayıcı | ✓ 8/8     | ✓ 4/4                 |
| **bu paket**               | ✓ 8/8     | ✓ 4/4                 |

Kapsayıcı biçimde ata ad alanı bildirimleri tepe öğeye taşınmalı ve ata
`xml:*` öznitelikleri miras alınmalıdır (C14N 1.0 §2.4). `SignedProperties`
referansı **her zaman** belge ortasında bir alt kümedir.

## Kapsam

### Bu sürümde var

|                     |                                                            |
| ------------------- | ---------------------------------------------------------- |
| **XAdES**           | BES, EPES, T, **LT**, **LTA** — beş seviye                 |
| **Zaman damgası**   | RFC 3161 — istek üretme, jeton doğrulama, seviye yükseltme |
| **İptal denetimi**  | RFC 6960 OCSP — istek üretme, yanıt doğrulama              |
| **CMS**             | RFC 5652 `SignedData` okuma ve doğrulama                   |
| **Yerleşim**        | `ubl-extension` (UBL-TR), `enveloped`                      |
| **Kanonikleştirme** | Canonical XML 1.0, Exclusive C14N, ±yorumlar               |
| **Özet**            | SHA-256, SHA-384, SHA-512                                  |
| **İmza**            | RSA-PKCS1, RSA-PSS, ECDSA                                  |
| **Anahtar**         | PKCS#12 — PBES2/AES, 3DES, RC2-40/128, RC4-40/128          |
| **Ayrık imzalama**  | `prepare()` / `complete()` — kart, HSM, uzak servis        |
| **Paralel imza**    | XPath Filter 2.0 ile                                       |

### Bu sürümde yok

**CAdES, PAdES, ASiC** — sırasıyla ikili veri, PDF ve konteyner imzası.
CAdES, XAdES-T ile birlikte yazılan CMS çekirdeğinin üstüne oturuyor;
PAdES CAdES'i yeniden kullanıyor. Sıra bu yüzden doğal:
**CAdES → PAdES → ASiC**.

**CRL ayrıştırma** — CRL'ler LT seviyesine gömülebiliyor ama içerikleri
çözümlenmiyor; iptal denetimi için OCSP yolu tam. CRL çözümlemesi
CAdES ile birlikte gelecek.

**PKCS#11** — akıllı kart ve HSM'e doğrudan erişim. Bugün de
kullanılabilirler: `prepare()` / `complete()` ile kendi PKCS#11
katmanınızı bağlayın. Yerleşik destek, yerel eklenti derlemesi gerektirdiği
için sıfır bağımlılık ilkesiyle ayrıca değerlendirilecek.

**Genel XPath** — ve eklenmesi planlanmıyor. İmza kapsamını belirleyen bir
ifadeyi yaklaşık değerlendirmek, imzanın kapsamadığı içeriği kapsıyormuş
gibi göstermektir. Tek bir iyi tanımlı deyim destekleniyor (bütün imzaları
çıkarma), gerisi açıkça reddediliyor.

**Sertifika zinciri ve iptal denetimi** — bilinçli olarak kapsam dışı.
Gerekçesi aşağıda.

## `valid: true` ne demek, ne demek değil

Demek olan üç şey:

1. Her `ds:Reference` özeti yeniden hesaplandı ve tuttu,
2. `ds:SignedInfo` kanonikleştirildi ve `ds:SignatureValue` bu baytlar
   üzerinde `ds:KeyInfo`'daki sertifikayla kriptografik olarak doğrulandı,
3. `xades:SigningCertificate` varsa, özeti kullanılan sertifikayla tutarlı.

Demek **olmayan** şeyler: sertifikanın güvenilir bir köke bağlandığı, iptal
edilmediği, imza anında geçerli olduğu ya da imzanın hukuken bağlayıcı
olduğu.

Bu ayrımı bulanıklaştırmak, imza kütüphanelerinde en sık görülen sahte
güvenlik kaynağıdır. Sertifikanın geçerlilik aralığıyla ilgili gözlemler
sessizce yutulmaz, `warnings` altında ayrıca raporlanır:

```ts
const sonuc = verify(imzali)
if (sonuc.valid && sonuc.warnings.length > 0) {
  for (const uyari of sonuc.warnings) console.warn(uyari.code, uyari.message)
}
```

Bir XAdES imzasının hukuki geçerliliği, kullanılan sertifikanın niteliğiyle
(nitelikli elektronik sertifika) ve imza politikasına uygunlukla ilgilidir;
kütüphanenin yapısal geçerlik denetimiyle karıştırılmamalıdır.

## Tasarım kararları

**SHA-1 yok.** Ne özet ne imza algoritması olarak. Çakışma üretmek 2017'den
beri pratikte mümkün. "Eski sistemlerle uyum" gerekçesiyle açık bırakmak,
kullanıcıyı zayıf bir imzaya bir seçenek kadar yakın tutmak olurdu.

**DTD tümden reddediliyor.** Varlık genişletme, harici varlık (XXE) ve
karesel şişme saldırılarının tamamı DTD üzerinden gelir. Dahası bir varlık,
imzalanan baytlarla doğrulanan baytların ayrışmasına yol açabilir — imzanın
anlamını kaybettiği durum tam olarak budur.

**Belirsiz kimlik reddediliyor.** `URI="#x"` ile aranan kimliği birden çok
öğe taşıyorsa `undefined` dönülür. "İlkini al" demek, saldırganın araya
kendi öğesini koyup imzanın kapsamını kaydırmasına izin vermektir — imza
sarma (signature wrapping) saldırısının klasik biçimi.

**Okurken hoşgörülü, yazarken katı.** Parçalara bölünmüş `OCTET STRING`
DER'de geçersizdir ama `pkijs` ile üretilmiş kaplarda vardır; okunuyor.
Yazarken her zaman ilkel biçim üretiliyor.

**Ata işaretçisi yok.** Kanonikleştirici belgeyi kökten dolaşıp ad alanı
bağlamını yanında taşır; alt ağaç kanonikleştirilirken bağlam elle
kopyalanmadığı için kaybolamaz da.

## Mimari

```
                   sign / verify          (tepe; her şeyi görür)
                         │
                       xades              (XML ile kripto burada buluşur)
                   ┌─────┴─────┐
                 c14n         pki         ← KARDEŞ, birbirini göremez
                   │           │
                  xml        asn1
                   └─────┬─────┘
                       core                (yaprak)
```

Kardeş izolasyonu ESLint ile uygulanıyor ve doğrudan doğrulanabilirlik
kazandırıyor: `c14n` hiçbir kriptografi görmediği için W3C'nin kendi test
vektörleriyle tek başına sınanabiliyor, `pki` ise hiç XML görmediği için
PKCS#12 çözümü bir imza akışı kurmadan sınanabiliyor.

## Geliştirme

```bash
npm install
npm test              # 328 test
npm run test:coverage
npm run typecheck
npm run lint
npm run knip
```

Testler iki bağımsız referans uygulamayla karşılaştırma yapar:
kanonikleştirme **libxml2** (`xmllint`), ASN.1 ve anahtar malzemesi
**OpenSSL** ile. İkisi de yoksa ilgili testler atlanır; CI'da ikisi de
kurulu.

Anahtar malzemesi depoda tutulmaz, her koşuda geçici dizinde üretilir.
Eski biçim kapları macOS'un sistem LibreSSL'iyle, modern olanlar OpenSSL 3
ile yazılır — bir kütüphanenin ikisini birden açabildiği ancak ikisini
birden üreterek gösterilebilir.

## Güvenlik

Güvenlik açıklarını herkese açık issue ile **değil**,
[özel güvenlik kanalından](https://github.com/yankikucuk/e-imza/security/advisories/new)
bildirin.

Özel anahtarınızı hiçbir koşulda paylaşmayın; bir hata bildirimi için
gerekmez. Kütüphane özel anahtarı diske yazmaz, ağa göndermez ve
günlüklemez.

## Sorumluluk reddi

Bu proje bağımsızdır; Gelir İdaresi Başkanlığı, TÜBİTAK ya da herhangi bir
entegratörle ilişkili değildir. ETSI ve W3C standartları ile kamuya açık
Türkçe belgeler üzerine kurulmuştur. Uygunluk değerlendirmesi gereken
senaryolarda denetimi kullanıcı yürütür.

## Lisans

MIT
