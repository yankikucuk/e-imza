# Güvenlik Politikası

Bu kütüphane elektronik imza üretir ve doğrular. Ürettiği imza bir belgeyi
hukuken bağlayıcı kılar; doğruladığı imza bir belgeye güvenilip
güvenilmeyeceğine karar verir. Her iki yön de hassastır ve tehdit modelleri
birbirinden farklıdır.

## Desteklenen sürümler

| Sürüm | Güvenlik düzeltmesi alır  |
| ----- | ------------------------- |
| `0.x` | Evet — en son yama sürümü |

`1.0.0` yayımlandığında bu tablo güncellenecektir. Düzeltmeler yalnızca en
son yayımlanan yama sürümü üzerinden gelir.

## Açık bildirme

**Güvenlik açıkları için herkese açık issue AÇMAYIN.** İmza doğrulayan bir
kütüphanedeki açığın ayrıntısı yama yayımlanmadan önce görünür olursa,
sahte imzayı geçerli saydırma yolu herkese açılmış olur.

Bildirim için GitHub'ın özel güvenlik danışma kanalını kullanın:

**[Security → Report a vulnerability](https://github.com/yankikucuk/e-imza/security/advisories/new)**

Bildiriminizde şunlar varsa değerlendirme hızlanır:

- Etkilenen sürüm ve Node.js sürümü
- Açığı tetikleyen **en küçük XML ya da DER parçası**
- Beklenen davranış ile gözlenen davranış
- Etkisi: geçersiz bir imza geçerli mi sayılıyor, geçerli bir imza mı
  reddediliyor, yoksa gizli bir veri mi sızıyor

### Asla göndermeyin

**Özel anahtarınızı.** Bir açığı göstermek için gerekmez; imzalı belge ve
varsa hata mesajı yeterlidir. Bir özel anahtar bir kez paylaşıldığında
sertifikanın iptali gerekir ve bu, bildirimin kendisinden çok daha pahalıya
mal olur.

**Gerçek bir mükellefe ait belgeyi.** Anonimleştirilmiş bir örnek yeterli;
açığı tetikleyen genellikle **yapı**dır, değerler değil.

Bir test sertifikası gerekiyorsa `tests/key-material.ts` içindeki betik
öz-imzalı bir tane üretir.

## Tehdit modeli

### 1. Sahte imzanın geçerli sayılması — en ağırı

Doğrulayıcının, imzalanmamış ya da değiştirilmiş bir içeriği imzalanmış
gibi göstermesi. Bu sınıfa karşı alınan yapısal önlemler:

**Anlaşılmayan hiçbir şey sessizce geçilmez.** Tanınmayan bir dönüşüm,
çözülemeyen bir referans, desteklenmeyen bir özet algoritması, dış URI ve
XPointer — hepsi açık hatayla reddedilir. Yok saymak, imzanın kapsamadığı
içeriği kapsıyormuş gibi göstermenin farklı biçimleridir.

**Belirsiz kimlik reddedilir.** `URI="#x"` ile aranan kimliği birden çok
öğe taşıyorsa referans çözülmez. "İlkini al" demek, saldırganın araya kendi
öğesini koyup imzanın kapsamını kaydırmasına izin vermektir — imza sarma
(signature wrapping) saldırısının klasik biçimi.

**Genel XPath yok.** İmza kapsamını belirleyen bir ifadeyi yaklaşık
değerlendirmek, kapsamı yanlış göstermektir. Tek bir iyi tanımlı deyim
destekleniyor, gerisi reddediliyor.

**SHA-1 yok.** Ne özet ne imza algoritması olarak. Çakışma üretmek 2017'den
beri pratikte mümkün.

**Örtük kanonikleştirme doğru uygulanır.** XMLDSig §4.3.3.2'ye göre
dönüşümsüz bir aynı-belge referansı kapsayıcı Canonical XML 1.0 ile
işlenir; `ds:CanonicalizationMethod` ne derse desin. Bunu karıştırmak, iki
uygulamanın farklı özet hesaplaması demektir.

### 2. Ayrıştırma sırasında kaynak tüketimi

Doğrulanacak belge karşı taraftan gelir; boyutunu, derinliğini ve yapısını
gönderen belirler.

- **DTD tümden reddedilir.** Varlık genişletme, harici varlık (XXE) ve
  karesel şişme saldırılarının tamamı DTD üzerinden gelir. Dahası bir
  varlık, imzalanan baytlarla doğrulanan baytların ayrışmasına yol
  açabilir.
- **XML boyut ve derinlik sınırı** — varsayılan 32 MiB ve 200 seviye,
  ayarlanabilir. Boyut sınırı ayrıştırmadan önce uygulanır.
- **DER iç içe geçme sınırı** — 64 seviye. `SEQUENCE` başlığı iki bayt
  olduğu için küçük bir girdiyle on binlerce seviye kurulabilir ve
  özyinelemeli bir ayrıştırıcı yığını taşırır.

### 3. Yan kanallar

- **Bütünlük ve özet karşılaştırmaları sabit zamanlıdır.** Erken çıkan bir
  karşılaştırma, doğru değeri bayt bayt tahmin etmeye yol açar.
- **PKCS#7 dolgu denetimi sabit zamanlıdır.** Erken çıkış klasik bir dolgu
  kâhini (padding oracle) açar.

### 4. Anahtar malzemesi

- Özel anahtar diske yazılmaz, ağa gönderilmez, günlüklenmez.
- PKCS#12 parolası bellekte tutulur ve türetme dışında kullanılmaz.
- `prepare()` / `complete()` akışında özel anahtar kütüphaneye hiç girmez.
- Depoda `.p12`, `.pfx`, `.key` ve `*-private.pem` dosyaları `.gitignore`
  ile engellidir. Bir özel anahtar bir kez depoya girerse geçmişten
  güvenilir biçimde silinemez.

## Kapsam dışı

Aşağıdakiler bu kütüphanenin **sorumluluğunda değildir** ve eksiklikleri
güvenlik açığı sayılmaz:

**Sertifika zinciri ve iptal denetimi.** `valid: true` yalnızca yapısal ve
kriptografik geçerliliği söyler: referans özetleri tuttu, imza değeri
sertifikanın açık anahtarıyla doğrulandı. Sertifikanın güvenilir bir köke
bağlandığı, iptal edilmediği ya da imza anında geçerli olduğu **anlamına
gelmez**. Bu denetimler çağıranın kendi güven kümesiyle yapılır.

Sertifikanın geçerlilik aralığıyla ilgili gözlemler yine de sessizce
yutulmaz, `warnings` altında raporlanır — ama `valid` sonucunu değiştirmez.

**RC2 ve RC4'ün zayıflığı.** İkisi de kırılmıştır ve pakette **yalnızca
çözme** yönüyle bulunurlar: amaç, eski araçlarla üretilmiş `.p12`
dosyalarını açabilmek. Şifreleme yönü kasten dışa açılmadı. Zayıf bir kabı
açabilmek, o kabın zayıflığını gidermez; anahtarınızı modern bir kaba
taşıyın.

**İmzanın hukuki geçerliliği.** Kullanılan sertifikanın niteliğiyle
(nitelikli elektronik sertifika) ve imza politikasına uygunlukla ilgilidir.

## Kütüphaneyi güvenli kullanmak

- **Parolayı koda gömmeyin.** Ortam değişkeni ya da bir sır yöneticisi
  kullanın.
- **`valid: true` gördükten sonra durmayın.** Sertifikanın beklediğiniz
  mükellefe ait olduğunu doğrulayın: `signer.subjectSerialNumber` alanı
  Türk sertifikalarında VKN ya da TCKN taşır.
- **`warnings` dizisini okuyun.** Boş olmayan bir uyarı listesi, imza
  yapısal olarak geçerli olsa bile dikkat gerektiğini söyler.
- **Gelen belgeye sınır koyun.** Varsayılan sınırlar geneldir; kendi
  ortamınız için daha dar olanı `parseXml` seçenekleriyle verin.
- **Zinciri ayrıca doğrulayın.** Kendi güven kümenizle, imza anına göre.

## Bu depodaki güvenlik önlemleri

- Çalışma zamanı bağımlılığı **yok** — tedarik zinciri yüzeyi yalnızca
  Node'un kendisi.
- CodeQL taraması ve bağımlılık incelemesi her PR'da.
- Kanonikleştirme libxml2, ASN.1 ve anahtar malzemesi OpenSSL ile bağımsız
  olarak karşılaştırılıyor.
- Kritik yollar mutasyon denemesiyle sınanıyor: imza denetiminin atlanması,
  özet karşılaştırmasının her zaman doğru dönmesi, imzanın belge özetinden
  çıkarılmaması gibi bozulmaların testlerden kaçmadığı ölçülüyor.
- npm yayınları **provenance** imzalı; paketin hangi commit'ten ve hangi
  iş akışından çıktığı doğrulanabilir.

## Teşekkür

Sorumlu bildirimde bulunanlar, aksini istemedikleri sürece yayımlanan
düzeltmenin sürüm notlarında anılır.
