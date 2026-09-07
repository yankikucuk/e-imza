/**
 * İmza-sadık XML düğüm modeli.
 *
 * Bu model, belge üretmek için değil, **imzalanmış baytları birebir geri
 * üretebilmek** için tasarlandı. Aradaki fark üç yerde görünür ve üçü de
 * incelenen kütüphanelerde gerçek hatalara yol açmıştı:
 *
 * 1. **Yorumlar ve işlem yönergeleri saklanır.** `#WithComments` biten bir
 *    kanonikleştirme algoritması bunları çıktıya yazar; atan bir model o
 *    algoritmayı hiç uygulayamaz.
 * 2. **Karışık içeriğe izin verilir.** Belge üretirken karışık içerik bir
 *    hatadır, ama imzalanan belgeyi biz üretmemiş olabiliriz. Gelen belgeyi
 *    "temizlemek", imzayı geçersiz kılmanın en hızlı yoludur.
 * 3. **Ad alanı bildirimleri normal özniteliklerden AYRI tutulur.**
 *    Kanonikleştirme ikisini farklı sıralar: bildirimler ön eke göre,
 *    öznitelikler (ad alanı URI'si, yerel ad) ikilisine göre. Tek listede
 *    tutup çıktıda ayırmaya çalışmak, `xml-crypto#538`'deki çift `xmlns`
 *    hatasının kaynağıdır.
 *
 * Düğümlerde **ata işaretçisi yoktur**. Kanonikleştirici belgeyi kökten
 * dolaşır ve ad alanı bağlamını yanında taşır; böylece bir alt ağaç tek
 * başına kanonikleştirilirken bile ata bağlamı her zaman doğrudur. Ata
 * işaretçisi tutan uygulamalarda bu bağlam elle kopyalanır ve kopyalama
 * eksik kaldığında `xmldsigjs#59` (kökte ön ek varsa imza bozuluyor) türü
 * hatalar çıkar.
 */

/** `xml` ön ekinin XML 1.0 tarafından sabitlenmiş ad alanı. */
export const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'

/** `xmlns` ön ekinin sabitlenmiş ad alanı. */
export const XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/'

/**
 * Bir ad alanı bildirimi — `xmlns="…"` ya da `xmlns:ön-ek="…"`.
 *
 * Varsayılan ad alanı bildiriminde {@link prefix} boş dizedir; bu, ön eksiz
 * öğelerin bağlandığı ad alanını gösterir.
 */
export interface XmlNamespaceDeclaration {
  /** Bildirilen ön ek; varsayılan ad alanı için `''`. */
  readonly prefix: string
  /** Ad alanı URI'si; `xmlns=""` (ad alanını iptal etme) durumunda `''`. */
  readonly uri: string
}

/**
 * Ad alanı bildirimi OLMAYAN bir öznitelik.
 *
 * `xmlns` ile başlayan öznitelikler bu tipe hiç girmez; onlar
 * {@link XmlElement.namespaceDeclarations} altında durur.
 */
export interface XmlAttribute {
  /**
   * Özniteliğin ad alanı URI'si. Ön eksiz öznitelikler ad alanısızdır —
   * öğelerden farklı olarak varsayılan ad alanını **miras almazlar**
   * (Namespaces in XML 1.0 §6.2). Bu kural sıkça yanlış uygulanır.
   */
  readonly namespace: string | undefined
  /** Kaynakta yazılmış ön ek; ön eksizse `undefined`. */
  readonly prefix: string | undefined
  /** Ön eksiz yerel ad. */
  readonly localName: string
  /**
   * Öznitelik değeri — XML 1.0 §3.3.3 uyarınca normalize edilmiş,
   * varlık başvuruları çözülmüş hâliyle. Kaçırma serileştirme anında yapılır.
   */
  readonly value: string
}

/** Metin düğümü. CDATA bölümleri de ayrıştırma sırasında bu tipe indirgenir. */
export interface XmlText {
  readonly kind: 'text'
  /** Satır sonları normalize edilmiş, varlıklar çözülmüş ham metin. */
  readonly value: string
}

/** Yorum düğümü — `<!-- … -->`. */
export interface XmlComment {
  readonly kind: 'comment'
  /** `<!--` ve `-->` arasındaki içerik. */
  readonly value: string
}

/** İşlem yönergesi — `<?hedef veri?>`. */
export interface XmlProcessingInstruction {
  readonly kind: 'pi'
  /** Yönergenin hedefi (ör. `xml-stylesheet`). */
  readonly target: string
  /** Hedeften sonraki içerik; yoksa `''`. */
  readonly value: string
}

/** Öğe düğümü. */
export interface XmlElement {
  readonly kind: 'element'
  /** Öğenin bağlandığı ad alanı URI'si; ad alanısızsa `undefined`. */
  readonly namespace: string | undefined
  /** Kaynakta yazılmış ön ek; ön eksizse `undefined`. */
  readonly prefix: string | undefined
  /** Ön eksiz yerel ad. */
  readonly localName: string
  /** Bu öğe ÜZERİNDE yapılan ad alanı bildirimleri (atalardan miras alınanlar değil). */
  readonly namespaceDeclarations: readonly XmlNamespaceDeclaration[]
  /** Ad alanı bildirimi olmayan öznitelikler. */
  readonly attributes: readonly XmlAttribute[]
  /** Alt düğümler; karışık içerik serbesttir. */
  readonly children: readonly XmlNode[]
}

/** Bir belgede yer alabilen her düğüm türü. */
export type XmlNode = XmlElement | XmlText | XmlComment | XmlProcessingInstruction

/** Ayrıştırılmış belge. */
export interface XmlDocument {
  readonly kind: 'document'
  /** Kök öğe. */
  readonly root: XmlElement
  /** Kök öğeden ÖNCE gelen yorum ve işlem yönergeleri (XML bildirimi hariç). */
  readonly prolog: readonly (XmlComment | XmlProcessingInstruction)[]
  /** Kök öğeden SONRA gelen yorum ve işlem yönergeleri. */
  readonly epilog: readonly (XmlComment | XmlProcessingInstruction)[]
}

/**
 * Öğenin ön ekli adı — kanonik çıktıda ve hata mesajlarında görünen ad.
 *
 * @param node - Adı istenen öğe ya da öznitelik
 * @returns `ön-ek:yerel-ad` ya da ön ek yoksa yalnızca yerel ad
 */
export const qualifiedName = (node: {
  readonly prefix: string | undefined
  readonly localName: string
}): string => (node.prefix === undefined ? node.localName : `${node.prefix}:${node.localName}`)

/**
 * Öğenin belirtilen özniteliğini bulur.
 *
 * @param element - Aranacak öğe
 * @param localName - Öznitelik yerel adı
 * @param namespace - Beklenen ad alanı; `undefined` ad alanısız öznitelik demektir
 * @returns Bulunan öznitelik ya da `undefined`
 */
export const getAttribute = (
  element: XmlElement,
  localName: string,
  namespace?: string,
): XmlAttribute | undefined =>
  element.attributes.find(
    (attribute) => attribute.localName === localName && attribute.namespace === namespace,
  )

/**
 * Öğenin belirtilen özniteliğinin değerini döndürür.
 *
 * @param element - Aranacak öğe
 * @param localName - Öznitelik yerel adı
 * @param namespace - Beklenen ad alanı
 * @returns Değer ya da öznitelik yoksa `undefined`
 */
export const getAttributeValue = (
  element: XmlElement,
  localName: string,
  namespace?: string,
): string | undefined => getAttribute(element, localName, namespace)?.value

/**
 * Öğenin doğrudan alt öğelerini verir (metin, yorum ve yönergeleri atar).
 *
 * @param element - Kaynak öğe
 * @returns Alt öğeler
 */
export const childElements = (element: XmlElement): readonly XmlElement[] =>
  element.children.filter((child): child is XmlElement => child.kind === 'element')

/**
 * Belirli ada sahip doğrudan alt öğeleri verir.
 *
 * @param element - Kaynak öğe
 * @param namespace - Aranan ad alanı URI'si
 * @param localName - Aranan yerel ad
 * @returns Eşleşen alt öğeler
 */
export const childrenNamed = (
  element: XmlElement,
  namespace: string,
  localName: string,
): readonly XmlElement[] =>
  childElements(element).filter(
    (child) => child.namespace === namespace && child.localName === localName,
  )

/**
 * Belirli ada sahip ilk doğrudan alt öğeyi verir.
 *
 * @param element - Kaynak öğe
 * @param namespace - Aranan ad alanı URI'si
 * @param localName - Aranan yerel ad
 * @returns İlk eşleşen alt öğe ya da `undefined`
 */
export const childNamed = (
  element: XmlElement,
  namespace: string,
  localName: string,
): XmlElement | undefined => childrenNamed(element, namespace, localName)[0]

/**
 * Bir öğenin altındaki tüm metni birleştirir.
 *
 * @param element - Kaynak öğe
 * @returns Alt ağaçtaki metin düğümlerinin sırayla birleşimi
 */
export const textContent = (element: XmlElement): string => {
  let out = ''
  const walk = (node: XmlNode): void => {
    if (node.kind === 'text') out += node.value
    else if (node.kind === 'element') for (const child of node.children) walk(child)
  }
  for (const child of element.children) walk(child)
  return out
}

/**
 * Alt ağaçtaki tüm öğeleri belge sırasına göre dolaşır.
 *
 * @param root - Başlangıç öğesi (kendisi de üretilir)
 * @yields Belge sırasında her öğe
 */
export function* walkElements(root: XmlElement): Generator<XmlElement> {
  yield root
  for (const child of root.children) {
    if (child.kind === 'element') yield* walkElements(child)
  }
}
