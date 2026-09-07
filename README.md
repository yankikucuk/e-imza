# @yankikucuk/e-imza

> **Durum: 0.1.0 — erken sürüm.** XAdES-BES/EPES imzalama ve doğrulama,
> kanonikleştirme, PKCS#12 kap okuma ve ayrık imzalama hazır ve
> sınanmış durumda. Public API henüz kararlı sayılmamalı; 1.0.0'a kadar
> kırıcı değişiklik olabilir. Zaman damgası (XAdES-T), CAdES, PAdES ve
> ASiC yol haritasında.

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

|                     |                                                     |
| ------------------- | --------------------------------------------------- |
| **XAdES**           | BES, EPES                                           |
| **Yerleşim**        | `ubl-extension` (UBL-TR), `enveloped`               |
| **Kanonikleştirme** | Canonical XML 1.0, Exclusive C14N, ±yorumlar        |
| **Özet**            | SHA-256, SHA-384, SHA-512                           |
| **İmza**            | RSA-PKCS1, RSA-PSS, ECDSA                           |
| **Anahtar**         | PKCS#12 — PBES2/AES, 3DES, RC2-40/128, RC4-40/128   |
| **Ayrık imzalama**  | `prepare()` / `complete()` — kart, HSM, uzak servis |
| **Paralel imza**    | XPath Filter 2.0 ile                                |

### Bu sürümde yok

**XAdES-T / LT / LTA** — zaman damgası, sertifika ve iptal verisi gömme.
RFC 3161 zaman damgası jetonu bir CMS `SignedData`'dır; ASN.1 katmanı
zaten yazıldığı için sıradaki iş bu.

**CAdES, PAdES, ASiC** — sırasıyla ikili veri, PDF ve konteyner imzası.
CAdES, XAdES-T için gereken CMS çekirdeğinin üstüne oturuyor; PAdES
CAdES'i yeniden kullanıyor. Sıra bu yüzden doğal: **XAdES → XAdES-T →
CAdES → PAdES → ASiC**.

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
npm test              # 258 test
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
