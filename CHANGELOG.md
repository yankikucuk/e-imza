# Değişiklik Günlüğü

Bu dosya [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) biçimini
ve [Semantic Versioning](https://semver.org/lang/tr/) kurallarını izler.

## [1.2.0] — 2026-09-07

XAdES-LT ve LTA. Beş seviyenin tamamı hazır.

### Eklendi

- `upgrade({ to: 'LT', certificates, ocspResponses, crls })` — zinciri ve
  iptal kanıtını `xades:CertificateValues` / `xades:RevocationValues`
  altına gömer
- `archiveTimestampRequest()` ve `upgrade({ to: 'LTA', token })` — imzanın
  ve o ana kadarki bütün imzalanmamış özelliklerin tamamını kapsayan arşiv
  zaman damgası
- RFC 6960 OCSP: `buildOcspRequest()`, `parseOcspResponse()`,
  `verifyOcspResponse()`
- Sertifika uzantıları: `ocspResponderUrls()`, `crlDistributionUrls()`,
  `caIssuerUrls()`, `certificateExtension()`
- `verify()` arşiv damgalarını da doğruluyor; `TimestampResult` artık
  `kind: 'signature' | 'archive'` taşıyor

### Kararlar

- **LT, iptal kanıtı olmadan reddediliyor.** Yalnızca zincir gömmek imzayı
  sertifikaların süresi dolduktan sonra doğrulanabilir kılmaz; sessizce
  kabul etmek sahte bir uzun-dönem güvencesi vermek olurdu
- **LTA seviyesi doğrulanmış bir ARŞİV damgası istiyor.** `SignatureTimeStamp`
  yeterli değil; yapıya bakıp LTA demek damganın amacını ortadan kaldırırdı
- **OCSP `CertID` özeti varsayılan SHA-1.** Bu, paketin "SHA-1 yok"
  ilkesinin bilinçli istisnası: buradaki özet bir güvenlik özeti değil,
  yanıtlayıcının hangi sertifikanın sorulduğunu bulmasına yarayan bir
  adlandırma özeti. RFC 6960 SHA-1 desteğini şart koşuyor ve sahadaki
  yanıtlayıcılar ezici çoğunlukla başka bir şey kabul etmiyor

### Doğrulama

OCSP, çevrimdışı bir OpenSSL yanıtlayıcısıyla iki yönde sınandı: ürettiğimiz
isteği OpenSSL okuyup imzalı yanıt üretiyor, yanıtını biz doğruluyoruz.
Hem "good" hem "revoked" durumu kapsanıyor.

On iki mutasyon denendi. İkisi ilk turda yakalanmadı ve ikisi de aynı
tuzağın örneğiydi: arşiv damgasını hem üreten hem doğrulayan biz olduğumuz
için, girdiden `ds:SignatureValue`yu ya da referans verisini çıkarmak
hiçbir testi düşürmüyordu — iki taraf aynı yanlışı yapıyordu. Girdinin
BİLEŞİMİNİ doğrudan sabitleyen ayrı bir iddia eklendi.

### Bilinen sınır

Arşiv damgasının girdi hesabı ETSI TS 101 903 v1.4.2 §8.2.1 uyarınca
yapılıyor; EN 319 132 farklı bir tanım verir. Zaman damgasının kendisi
OpenSSL ile çapraz doğrulandı, ama arşiv girdisinin hesabı bağımsız bir
uygulamayla doğrulanamadı.

328 test.

## [1.1.0] — 2026-09-07

XAdES-T: RFC 3161 zaman damgası ve CMS okuma.

### Eklendi

- `timestampRequest()` — imza için RFC 3161 istek baytları. Damgalanan şey,
  ETSI TS 101 903 §7.3 uyarınca kanonikleştirilmiş `ds:SignatureValue`
  **öğesidir**, içindeki base64 metin değil
- `upgrade({ to: 'T', token })` — jetonu `xades:UnsignedProperties` altına
  yerleştirir. Jetonun bu imzayı damgaladığı önce doğrulanır; tutmuyorsa
  hata verir
- `verify()` artık bulduğu her damgayı **gerçekten doğruluyor**. Sonuç
  `timestamps[]` alanıyla geldi
- RFC 3161 katmanı ayrıca dışa açık: `buildTimestampRequest()`,
  `parseTimestampResponse()`, `parseTstInfo()`, `verifyTimestampToken()`
- CMS (RFC 5652) `SignedData` okuma ve doğrulama: `parseCmsSignedData()`,
  `verifyCmsSigner()`, `signedAttribute()`

### Değişti

- **Doğrulanmayan bir zaman damgası artık seviyeyi yükseltmiyor.** Belge
  `<xades:SignatureTimeStamp>` içerse bile jeton tutmuyorsa `level` değeri
  `BES`/`EPES` kalıyor ve `warnings` içinde `timestamp-invalid` çıkıyor.
  Yapıya bakıp "T" demek damganın var oluş amacını ortadan kaldırırdı —
  o etiketi belgeye herkes yazabilir
- `childNamed` ve `childrenNamed` ad alanı olarak `undefined` kabul ediyor;
  ad alanısız öğeler artık bulunabiliyor

### Doğrulama

Zaman damgası kodu çevrimdışı bir OpenSSL TSA'sıyla **iki yönde** sınandı:
ürettiğimiz `TimeStampReq`'i OpenSSL kabul edip jeton üretiyor, ve OpenSSL'in
ürettiği jetonu bizim doğrulayıcımız kabul ediyor. Tek yönlü bir test
yalnızca kendimizle tutarlı olduğumuzu gösterirdi.

Yedi mutasyon denendi. Biri ilk turda yakalanmadı ve gerçek bir açıktı: CMS
`messageDigest` denetimi kaldırılınca hiçbir test düşmüyordu. O denetim
olmadan saldırgan, CMS imzasını bozmadan jetonun içeriğini — yani damganın
bildirdiği **zamanı** — değiştirebilir; imza `signedAttrs` üzerinde
hesaplandığı için `eContent`e dokunmak onu düşürmez. Testi eklendi.

296 test; ifade %93,1, satır %95,6, fonksiyon %99,2.

## [1.0.0] — 2026-09-07

İlk sürüm. XAdES imzalama ve doğrulama, kanonikleştirme, PKCS#12 kap okuma.

### Eklendi

**İmzalama**

- `sign()` — XAdES-BES ve EPES; `ubl-extension` (UBL-TR e-Fatura,
  e-İrsaliye) ve `enveloped` yerleşimleri
- `prepare()` / `complete()` — özel anahtara erişilmeden imzalama. Akıllı
  kart, donanım güvenlik modülü ve uzak imza servisleri için; kartların
  istediği üç biçim de veriliyor (kanonik baytlar, ham özet, DER
  `DigestInfo`)
- `parallel: true` — XPath Filter 2.0 ile birbirinden bağımsız paralel
  imzalar
- RSA-PKCS1, RSA-PSS ve ECDSA; SHA-256/384/512. ECDSA imzası XMLDSig'in
  şart koştuğu ham `r‖s` biçiminde

**Doğrulama**

- `verify()` ve `verifyAll()` — referans özetleri, imza değeri ve
  `xades:SigningCertificate` tutarlılığı
- Sertifika geçerlilik aralığı gözlemleri `warnings` altında; `valid`
  sonucunu değiştirmiyor
- Tanınmayan dönüşüm, çözülemeyen referans, dış URI, XPointer ve belirsiz
  kimlik açık hatayla reddediliyor

**Kanonikleştirme**

- Canonical XML 1.0 ve Exclusive C14N, yorumlu ve yorumsuz
- Alt küme kanonikleştirmesi ata bağlamını belgeden okur
- Çıkarılacak düğüm kümesi dışarıdan verilebilir

**Anahtar malzemesi**

- `loadPkcs12()` — PBES2/AES, 3DES, RC2-40/128 ve RC4-40/128 şifreli kaplar
- RC2 (RFC 2268) ve RC4 saf JavaScript olarak, yalnızca çözme yönüyle
- Uç sertifika, özel anahtarla eşleşen sertifikadır

**XML ve ASN.1**

- İmza-sadık ayrıştırıcı ve gidiş-dönüş güvenli serileştirici
- DER okuyucu ve yazıcı

### Doğrulama

- W3C `REC-xml-c14n-20010315` §3.1–3.6 uygunluk vektörleri
- libxml2 ile fark testi — dokuz belge, iki algoritma
- RFC 2268'in sekiz RC2 vektörü, iki yönde
- OpenSSL ile ASN.1 çapraz doğrulaması
- `xadesjs` ile birlikte çalışabilirlik ölçümü
- 11 mutasyon denemesi

258 test; ifade %93,9, satır %96,2, fonksiyon %98,6.

### Bilinen sınırlar

- XAdES-T / LT / LTA yok — zaman damgası ve iptal verisi gömme
- CAdES, PAdES, ASiC yok
- PKCS#11 yerleşik değil; `prepare()` / `complete()` ile dışarıdan bağlanır
- Genel XPath desteklenmiyor ve planlanmıyor

[1.2.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.2.0
[1.1.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.1.0
[1.0.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.0.0
