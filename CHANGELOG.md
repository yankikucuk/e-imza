# Değişiklik Günlüğü

Bu dosya [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) biçimini
ve [Semantic Versioning](https://semver.org/lang/tr/) kurallarını izler.

## [0.1.0] — 2026-09-07

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

[0.1.0]: https://github.com/yankikucuk/e-imza/releases/tag/v0.1.0
