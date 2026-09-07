## Ne değişti

<!-- Değişikliği ve nedenini kısaca anlatın. -->

## Neden

<!-- Hangi problemi çözüyor? Bir issue'ya bağlıysa: Closes #123 -->

## Nasıl doğrulandı

<!--
Testin GEÇTİĞİNİ yazmak yetmez; testin BAŞARISIZ OLABİLDİĞİNİ gösterin.
Yeni bir test eklediyseniz, koruduğu üretim satırını geçici olarak
kaldırıp testin kırmızı olduğunu doğrulayın ve çıktıyı buraya yapıştırın.
-->

- [ ] `npm test` geçiyor
- [ ] `npm run typecheck && npm run lint` temiz
- [ ] Yeni test eklendiyse, korumasız hâlde kırmızı olduğu doğrulandı
- [ ] Üretilen XML değiştiyse altın dosya testleri güncellendi

## Kontrol listesi

- [ ] Çalışma zamanı bağımlılığı eklemedim (`dependencies` boş kalmalı)
- [ ] builders / parsers / validators arasında import eklemedim
- [ ] Public API değiştiyse JSDoc, README ve CHANGELOG güncellendi
- [ ] Fixture eklediysem gerçek bir mükellefe ait veri içermiyor
- [ ] Mevzuat iddiası varsa kılavuzun sürümü ve bölümü yazıldı
