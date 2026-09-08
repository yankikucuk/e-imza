# Değişiklik Günlüğü

Bu dosya [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) biçimini
ve [Semantic Versioning](https://semver.org/lang/tr/) kurallarını izler.

## [1.8.0] — 2026-09-08

Kod denetimi. İki bulgu da düşmanca girdiyle üretildi, sonra düzeltildi.

### Düzeltildi

- **Aşırı iç içe bir PDF ayrıştırıcının çağrı yığınını tüketiyordu.** Yaklaşık
  5.000 düzey iç içe dizi ya da sözlük içeren bir belge `readPdf()` çağrısını
  `RangeError: Maximum call stack size exceeded` ile düşürüyordu — yani
  saldırganın hazırladığı bir dosya, doğrulayıcıyı kütüphanenin kendi hata
  yolundan çıkarabiliyordu. XML ayrıştırıcısında zaten olan derinlik sınırı
  artık PDF tarafında da var (200 düzey, aynı değer) ve aşıldığında
  yakalanabilir bir ayrıştırma hatası veriyor
- **PDF ve ZIP ayrıştırıcıları kütüphane ağacının dışında hata fırlatıyordu.**
  `errors.ts` tek bir söz veriyor: fırlatılan her hata `EImzaError` soyundan
  gelir, çünkü "girdi bozuk" ile "kodda bug var" karışırsa geçersiz bir imza
  sessizce yutulabilir. Oysa bu iki ayrıştırıcı 28 yerde yerleşik
  `SyntaxError` fırlatıyordu — üstelik tam da güvenilmeyen baytların
  okunduğu yerlerde

### Eklendi

- `PdfSyntaxError` ve `ZipSyntaxError`; ikisi de `EImzaError` soyundan.
  Diğer hata sınıfları gibi ön eki kendileri ekliyor
- Bozuk girdi test paketi: kesilmiş, uzunluğu yalan söyleyen, aşırı derin ve
  rastgele baytlarla DER, XML ve PDF giriş noktaları. Sözleşme tek cümle —
  ya başarılı olur ya `EImzaError` verir; ne yabancı bir hata ne de asılma
- PDF nesne derinliği için gerileme testleri

### Dikkat

`readPdf()`, `readZip()` ve bunları kullanan yollar artık `SyntaxError`
yerine `PdfSyntaxError` / `ZipSyntaxError` fırlatıyor. Her ikisi de
`EImzaError` soyundan; `e.message` okuyan ya da `EImzaError` yakalayan kod
etkilenmez. Yalnızca `e instanceof SyntaxError` yazan kod güncellenmeli —
belgelenmiş yol bu olmadığı ve hata ağacı sözü zaten bunu vaat ettiği için
küçük sürüm olarak yayımlanıyor.

## [1.7.1] — 2026-09-07

Yalnızca belge. Kod değişmedi.

### Değişti

- **README baştan yazıldı.** Anlatım artık "başka bir paketin şu hatası var"
  yerine "bu paket şu işi şöyle yapıyor" ekseninde. Karşılaştırma tabloları
  ve issue numaraları kaldırıldı; ölçülen teknik bulgular ve bağımsız
  doğrulama kanıtları olduğu gibi korundu
- Bağımsız tanık olarak kullanılan araçlar (libxml2, OpenSSL, poppler,
  Info-ZIP) elbette adıyla anılmaya devam ediyor — çapraz doğrulama
  iddiasının anlamı buna bağlı
- Kapsam tablosuna ASiC satırı eklendi; "Bu sürümde yok" bölümü gözden
  geçirildi
- Her sürümde yapılan mutasyon denemesi "Geliştirme" bölümünde anlatıldı

### Duyuru

- **PKCS#11 ayrı bir pakete taşınıyor:** `@yankikucuk/e-imza-pkcs11`.
  Yerleşik destek yerel bir eklenti gerektirdiği için bu paketin sıfır
  bağımlılık ilkesini kırardı. Ayrı paket olarak isteyen kurar, istemeyen
  etkilenmez; `prepare()` / `complete()` bugün de kendi PKCS#11 katmanınızı
  bağlamaya yetiyor

## [1.7.0] — 2026-09-07

CAdES-LTA — `archive-time-stamp-v3`. Üç imza biçiminin üçü de artık arşiv
seviyesine kadar tam.

### Eklendi

- `cadesArchiveTimestamp()` — ETSI TS 101 733 §6.4.3 arşiv zaman damgası;
  `prepare`/`finish` deyimi, `ATSHashIndex` istekle yerleştirme arasında
  tek bir kapanışta tutuluyor
- `buildAtsHashIndex()`, `parseAtsHashIndex()`, `checkAtsHashIndex()`,
  `readArchiveComponents()`, `archiveTimestampInput()` — §6.4.2'nin
  `ats-hash-index` yapısı, hem üretme hem inceleme için
- `cadesVerify()` artık ATSv3'ü **gerçekten doğruluyor**: girdiyi jetondaki
  indeksle yeniden kurup `messageImprint`e bağlıyor, indeksin belgedeki
  bileşenleri karşıladığını ayrıca denetliyor (`coversAllComponents`)
- Seviye `LTA`'ya çıkabiliyor — yalnızca doğrulanan arşiv damgasıyla

### Düzeltildi

- **`sid` ile `signedAttrs` karışıyordu.** `SignerInfo.sid` bir CHOICE'tır
  ve `subjectKeyIdentifier` seçildiğinde o da `[0]` etiketi taşır;
  `signedAttrs` yapının başından arandığı için SKI ile imzalanmış her
  yapıda `sid` `signedAttrs` sanılıyordu. Sonuç sessizdi: imza tamamen
  yanlış baytlar üzerinde doğrulanıyordu. `openssl cms -sign -keyid` ile
  üretilen bir yapıyla gerileme testine bağlandı. Bazı TSA'lar jetonlarında
  SKI kullanıyor

### Kararlar

- **ATSv2 üretilmiyor ve doğrulanmıyor.** Girdi hesabı ATSv3'ten farklı;
  belgede varsa `archive-timestamp-v2-unverified` uyarısı çıkıyor ve seviye
  yükselmiyor
- **`unsignedAttrs` girdiye girmiyor** (§6.4.3 madde 3) — girseydi damga
  eklendiği anda kendi girdisini değiştirirdi. Korumasız da kalmıyor:
  `ATSHashIndex` üzerinden girdinin dördüncü bileşenine giriyor
- **Girdinin ikinci bileşeni içeriğin ÖZETİ**, içeriğin kendisi değil
  (§6.4.3 madde 2) — ve özet arşiv damgasının algoritmasıyla alınıyor
- `SignerInfo` alanları kaynaktaki ham dilimleriyle taşınıyor; `signedAttrs`
  burada `[0] IMPLICIT` etiketini KORUYOR (imzalama hesabındaki `SET`e
  çevirme kuralı §6.4.3'te geçerli değil)

### Doğrulamanın sınırı — dürüstçe

CAdES arşiv damgasının **girdi hesabını sınayacak bağımsız bir uygulama
bulunamadı**; bu formatı doğrulayan olgun açık kaynaklı uygulama ETSI DSS
(Java) ve bu paketin test zinciri Node ile sınırlı. Bunun yerine üç ayrı
bağımsız tanık kullanıldı:

- `openssl ts -verify -token_in` — jetonun imzası ve `messageImprint`in
  ürettiğimiz girdinin özeti oluşu
- `openssl asn1parse` — `SignerInfo` alanlarının ham dilimleri,
  `ATSHashIndex` kodlaması ve OID (OpenSSL onu `id-aa-ATSHashIndex` diye
  adlandırıyor)
- `openssl dgst` / `openssl pkcs7` — indeksteki her özet ve sertifika sayısı

**Kalan boşluk:** bileşenlerin sırası standardın metninden alındı ve bir
ETSI uygulamasıyla karşılaştırılamadı. Üretime almadan önce karşı tarafın
doğrulayıcısıyla denenmeli.

### Doğrulama

- 20 yeni test; toplam 511
- Mutasyon denemesi: 13 kasıtlı hata, ilk turda 2'si kaçtı — doğrulamanın
  jetonu girdiye BAĞLAMAMASI ve sertifika indeksinin eksik üretilmesi.
  İkisi de gerçek boşluktu ve teste bağlandı. İkincisi bu depodaki tekrar
  eden tuzağın ders kitabı örneği: hem üretici hem doğrulayıcı aynı
  fonksiyonu çağırdığı için beklenti de hatayla birlikte küçülüyordu;
  çözüm, sayıyı OpenSSL'e ve ayrı bir ayrıştırıcıya saydırmak oldu

## [1.6.0] — 2026-09-07

PAdES-LT ve PAdES-LTA — PDF'te uzun dönem doğrulanabilirlik.

### Eklendi

- `padesUpgrade({ to: 'LT' })` — `/DSS` (Document Security Store) ile
  sertifika, OCSP yanıtı ve CRL'i belgeye gömme; var olan `/DSS` korunup
  genişletiliyor
- `padesDocumentTimestamp()` — `/DocTimeStamp` (`/SubFilter /ETSI.RFC3161`)
  belge zaman damgası; `prepare`/`finish` deyimi, jeton gömülmeden önce bu
  baytları damgaladığı denetleniyor
- `readDocumentSecurityStore()`, `vriKey()`, `addDocumentSecurityStore()`
- `padesVerify()` artık her imza için `level` (`B-B`/`B-T`/`B-LT`/`B-LTA`)
  ve `hasVri` bildiriyor; `/DocTimeStamp` damgaları ayrı bir
  `documentTimestamps` dizisinde doğrulanıyor
- `streamData()` — PDF akış verisini süzgeçten geçirip verir

### Değişti

- `padesVerify()` sonucuna `documentTimestamps` ve `dss` alanları eklendi;
  var olan alanlar korundu (geriye dönük uyumlu)
- İmza alanı yerleştirme, imza ve belge damgası arasında **ortak** bir
  modüle çıkarıldı; `/ByteRange` hesabının iki yerde ayrışması yapısal
  olarak imkânsız hâle geldi

### Kararlar

- **Seviye yalnızca doğrulanan kanıtla yükseliyor.** Gömülü ama tutmayan
  bir damga `B-LTA` yapmaz, `document-timestamp-invalid` uyarısı çıkarır
- **Basamak atlanmıyor.** `/DSS` varken imza zaman damgası yoksa seviye
  `B-B` kalır; ETSI, `B-LT`nin `B-T` üzerine kurulmasını şart koşuyor
- **`/VRI` anahtarı `/Contents` baytlarının SHA-1'i — sıfır dolgusu
  dahil.** Spesifikasyon netleştirmiyor; dolgulu hâl seçildi çünkü yaygın
  uygulamalar (iText, PDFBox tabanlı ETSI DSS) böyle hesaplıyor ve `/VRI`nin
  tek işlevi başka bir doğrulayıcıyla eşleşmek. Test bu değeri **OpenSSL'e**
  hesaplatıp karşılaştırıyor
- **Damga sözlüğüne `/M` yazılmıyor.** Zaman, jetonun içindeki TSA'nın
  söylediğidir; ikinci bir kaynak koymak çelişki üretirdi
- **CRL'ler gömülüyor ama seviye yükseltmiyor.** İçerikleri çözümlenmediği
  için iptal kanıtı sayılmıyorlar

### Doğrulama

- 31 yeni test; toplam 491
- `pdfsig`, belge damgasını ayrı bir imza alanı olarak görüp `/ByteRange`ını
  kendi hesaplayarak `Total document signed` diyor
- `openssl dgst -sha1`, `/VRI` anahtarını bağımsız olarak doğruluyor
- Mutasyon denemesi: 13 kasıtlı hata, ilk turda 3'ü kaçtı (seviye hesabında
  `/VRI` ile malzemenin karıştırılması, `/Type /Sig` yazılmış damganın
  tanınması, yinelenen sertifikaların ayıklanması) — üçü de teste bağlandı

## [1.5.0] — 2026-09-07

ASiC — imzalı konteyner. ASiC-S ve ASiC-E.

### Eklendi

- `createAsic()`, `readAsic()` — konteyner üretme ve okuma
- ASiC-E + CAdES için `ASiCManifest` üretimi; okurken referans edilen
  dosyaların özetleri yeniden hesaplanıp karşılaştırılıyor
- Sıfır bağımlılıklı ZIP katmanı: `createZip()`, `readZip()`,
  `peekFirstEntry()`, `crc32()`

### Kararlar

- **ASiC imza üretmez, paketler.** İçine konan imzanın biçimine bakmıyor;
  standardın kendi ayrımı bu
- **ASiC-S kısıtları esnetilmiyor.** Birden çok dosya ya da imza açık hata
  veriyor; esnetmek konteyneri okuyan diğer uygulamaların reddetmesine yol
  açardı
- **Manifest okunurken doğrulanıyor.** Özetleri kontrol etmemek, imzanın
  kapsadığını iddia ettiği dosyanın gerçekten o dosya olduğunu varsaymak
  olurdu
- **ZIP64 ve şifreli ZIP desteklenmiyor.** ASiC konteynerleri bunları
  kullanmaz; "belki lazım olur" diye eklemek sınanmamış kod demek

### Doğrulama

**Info-ZIP (`unzip`) çapraz doğrulaması.** Ürettiğimiz arşivleri `unzip -t`
sağlam buluyor, `-l` listeliyor, `-p` içeriği doğru açıyor.

Altı mutasyon denendi; ikisi ilk turda yakalanmadı ve ikisi de gerçek bir
dayanıklılık boşluğuydu — ikisi de "kendi yazdığımız arşivlerde ikisi hep
aynı" tuzağının örneği:

- **Verinin konumu yerel başlıktan okunmalı.** Merkezî dizindeki ad ve ek
  alan uzunlukları yerel başlıktakinden FARKLI olabilir; ZIP bunu
  yasaklamıyor. Merkezî uzunlukları kullanan bir okuyucu yanlış konumdan
  okur ve HATA VERMEZ. Testi, yerel başlığında ek alan olan ama merkezî
  dizininde olmayan bir arşiv elle kurgulanarak yazıldı.
- **Açılan boyut denetimi.** Beyan edilenden farklı çıkan bir girdi, imzanın
  kapsadığı veriden farklı bir veri demektir; sessizce kabul edilmemeli.

460 test.

## [1.4.0] — 2026-09-07

PAdES — PDF imzası. B-B ve B-T.

### Eklendi

- `padesSign()`, `padesVerify()` — artımlı güncelleme ile PDF imzası
- `padesPrepare()` / `padesComplete()` — kart, HSM ve uzak imza için
- PDF yapı katmanı: nesne ayrıştırıcısı, çapraz başvuru tablosu ve akışı,
  nesne akışı (`ObjStm`), PNG öngörücüsü, artımlı güncelleme yazıcısı
- `readPdf()`, `catalog()`, `firstPage()`, `getObject()` — PDF okuma
  yardımcıları da dışa açık

### Kararlar

- **Özgün baytlara dokunulmuyor.** İmza dosyanın sonuna ekleniyor, eski
  çapraz başvuru `/Prev` ile zincirleniyor. Daha önce atılmış imzalar bu
  yüzden bozulmuyor ve üst üste imza atılabiliyor
- **Kapsam raporlanıyor.** İkinci imza eklendiğinde birincinin kapsamı
  daralır; `coversWholeDocument: false` ve `partial-coverage` uyarısı
  çıkar. Sessizce "geçerli" demek, imzanın kapsamadığı içeriği kapsıyormuş
  gibi göstermek olurdu
- **Şifreli PDF açıkça reddediliyor.** İmza eklemek belgeyi çözmeyi
  gerektirir
- **İmza alanı sığmazsa açık hata.** Sessizce kırpmak bozuk dosya üretirdi

### Doğrulama

**poppler `pdfsig` çapraz doğrulaması.** Bağımsız bir PDF imza
doğrulayıcısı imzalarımızı `Signature is Valid` ve `Total document signed`
diye raporluyor — tek sonuç, artımlı güncellemenin, `/ByteRange` hesabının,
imza sözlüğünün ve gömülü CAdES'in hepsini birlikte kanıtlıyor.

Yedi mutasyon denendi, altısı yakalandı. Yakalanmayan biri gerçek bir test
boşluğu DEĞİL, ölçülemez bir dal: `/Contents` yer tutucusu zaten sıfırlarla
dolu olduğu için imzadan artan bölgeyi ayrıca sıfırla doldurmak
gözlemlenebilir bir fark yaratmıyor. Savunma amaçlı bırakıldı, gerekçesi
koda yazıldı, ve yer tutucunun gözlemlenebilir sözleşmesi ayrı bir testle
sabitlendi.

### Katman kuralı

`pdf` katmanı kriptografiyi **hiç görmez** — `xml` katmanının PDF'teki eşi.
`pades` ikisinin üstünde durur ve XAdES tarafını görmez. Hepsi ESLint ile
zorlanıyor.

427 test.

## [1.3.0] — 2026-09-07

CAdES — ikili veri imzası. BES, EPES, T ve LT.

### Eklendi

- `cadesSign()`, `cadesVerify()` — gömülü ve ayrık imza
- `cadesPrepare()` / `cadesComplete()` — kart, HSM ve uzak imza için;
  XAdES'teki desenin aynısı
- `cadesTimestampRequest()` ve `cadesUpgrade({ to: 'T' | 'LT' })`
- CMS `SignedData` **üretimi** (RFC 5652); okuma 1.1.0'da gelmişti
- İmzalanmış öznitelikler: `signingCertificateV2` (RFC 5035),
  `signaturePolicyIdentifier`, `commitmentTypeIndication`, `signerLocation`

### Doğrulama

**OpenSSL çapraz doğrulaması.** `openssl cms -verify` ürettiğimiz imzaları
kabul ediyor: gömülü, ayrık, SHA-384/512, EC anahtar, EPES, T'ye ve LT'ye
yükseltilmiş hâlleriyle. Bu tek test `signedAttrs` kodlamasını, `SET`
etiketi dönüşümünü, `SignerInfo` alan sırasını ve `messageDigest` bağını
birlikte kanıtlıyor.

Sekiz mutasyon denendi; ikisi ilk turda yakalanmadı ve ikisi de gerçek
boşluktu:

- **Sertifika bağı hiç sınanmıyormuş.** `signingCertificateV2` denetimini
  "her zaman doğru" yapan mutasyon hiçbir testi düşürmüyordu — oysa o bağ
  CAdES-BES'in tam kalbi. Testi düşük seviyeli parçalarla tutarsız bir yapı
  kurarak yazıldı: imza A sertifikasıyla atılıyor, öznitelik B'nin özetini
  taşıyor. OpenSSL böyle bir imzayı kabul ediyor (kriptografik olarak
  geçerli), biz uyarıyoruz.
- **`signingTime` biçimi.** RFC 5652 §11.3 1950–2049 arasını `UTCTime`
  olarak kodlamayı ŞART koşuyor; `GeneralizedTime` yazan mutasyon
  yakalanmıyordu çünkü OpenSSL de bizim ayrıştırıcımız da ikisini kabul
  ediyor. Katı bir doğrulayıcı reddederdi.

### Katman kuralı

`cades` XML'i **hiç görmez** ve bu ESLint ile zorlanıyor. Kısıtlama değil,
tanım: CAdES ikili veri imzasıdır.

352 test.

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

[1.5.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.5.0
[1.4.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.4.0
[1.3.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.3.0
[1.2.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.2.0
[1.1.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.1.0
[1.0.0]: https://github.com/yankikucuk/e-imza/releases/tag/v1.0.0
