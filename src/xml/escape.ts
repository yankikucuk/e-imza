/**
 * Kanonik çıktı kaçırma kuralları — Canonical XML 1.0 §2.3, "Special
 * Characters Outside Markup" ve "Attribute Values".
 *
 * Üç ayrı kural vardır ve birbirinin yerine kullanılamaz. Tek bir "XML
 * kaçır" fonksiyonu yazıp üç yerde çağırmak, kanonik çıktıyı sessizce
 * bozar: metinde `"` kaçırılmaz, öznitelikte `>` kaçırılmaz, yorumda
 * hiçbiri kaçırılmaz.
 */

/**
 * Metin düğümü içeriğini kaçırır.
 *
 * `>` karakteri, metin içinde teknik olarak kaçırılmak zorunda değildir
 * (yalnızca `]]>` dizisinde sorun çıkarır) ama kanonik biçim onu **her
 * zaman** kaçırır. Bu, kanonikleştirmenin belirli olmasının koşuludur:
 * kaynağın `>` mi `&gt;` mi yazdığına bakılmaksızın çıktı aynıdır.
 *
 * @param text - Ham metin
 * @returns Kanonik biçimde kaçırılmış metin
 */
export const escapeText = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;')

/**
 * Öznitelik değerini kaçırır.
 *
 * Metinden iki farkı vardır: `"` kaçırılır (değer her zaman çift tırnakla
 * yazıldığı için), `>` kaçırılmaz. Ayrıca sekme ve satır başı karakter
 * başvurusuna dönüşür — çünkü ayrıştırma sırasında DÜZ yazılmış boşluklar
 * zaten tek boşluğa indirgenmiştir; burada hâlâ sekme ya da satır sonu
 * görüyorsak, kaynakta karakter başvurusuyla yazılmış demektir ve o niyet
 * korunmalıdır.
 *
 * @param value - Normalize edilmiş öznitelik değeri
 * @returns Kanonik biçimde kaçırılmış değer
 */
export const escapeAttributeValue = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;')
    .replace(/\r/g, '&#xD;')

/**
 * Yorum ve işlem yönergesi içeriğini kaçırır.
 *
 * Burada yalnızca satır başı kaçırılır; `&` ve `<` yorumun içinde işaretleme
 * sayılmadığı için dokunulmaz.
 *
 * Satır başı kaçırma, {@link parseXml} ile okunmuş bir belgede hiç
 * tetiklenmez: satır sonu normalizasyonu ayrıştırmadan önce çalışır ve
 * yorumlar karakter başvurusu tanımadığı için `&#xD;` orada düz metin
 * kalır. Dal yine de gereklidir — imza yapıları bellekte PROGRAMLA
 * kurulur ve oraya CR taşıyan bir yorum yerleştirilebilir.
 *
 * @param value - Ham içerik
 * @returns Kanonik biçimde kaçırılmış içerik
 */
export const escapeCommentOrInstruction = (value: string): string => value.replace(/\r/g, '&#xD;')

/**
 * İki dizeyi **kod noktası** sırasına göre karşılaştırır.
 *
 * JavaScript'in `<` işleci dizeleri UTF-16 kod BİRİMİ sırasına göre
 * karşılaştırır. Bu, temel çok dilli düzlem dışındaki karakterlerde
 * (`U+10000` ve üstü) kod noktası sırasından ayrılır: vekil çift, `U+E000`
 * ile `U+FFFF` arasındaki karakterlerden küçük görünür. Kanonik sıralama
 * kod noktası sırasıdır; XML adlarında astral karakter nadirdir ama
 * "nadir" ile "olmaz" aynı şey değildir ve doğru karşılaştırma ucuzdur.
 *
 * @param a - Birinci dize
 * @param b - İkinci dize
 * @returns `a < b` ise negatif, eşitse 0, `a > b` ise pozitif
 */
export const compareCodePoints = (a: string, b: string): number => {
  // `no-misused-spread` burada kasten devre dışı: kuralın uyardığı davranış —
  // dizeyi KOD NOKTALARINA ayırmak — bu fonksiyonun tam olarak istediği şey.
  // Kuralın önerdiği `Intl.Segmenter` yerelleşmiş grafem kümeleri üretir;
  // kanonik sıralama ise yerelden bağımsız kod noktası sırasıdır.
  /* eslint-disable-next-line @typescript-eslint/no-misused-spread */
  const left = [...a]
  /* eslint-disable-next-line @typescript-eslint/no-misused-spread */
  const right = [...b]
  const shared = Math.min(left.length, right.length)
  for (let i = 0; i < shared; i += 1) {
    const x = (left[i] ?? '').codePointAt(0) ?? 0
    const y = (right[i] ?? '').codePointAt(0) ?? 0
    if (x !== y) return x - y
  }
  return left.length - right.length
}
