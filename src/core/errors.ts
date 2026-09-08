/**
 * Bu kütüphanenin fırlattığı her hatanın ortak atası.
 *
 * Tek bir kök sınıf olması, çağıranın `catch (e) { if (e instanceof
 * EImzaError) … }` ile kütüphane hatalarını beklenmedik çalışma zamanı
 * hatalarından ayırmasını sağlar. Bu ayrım imza kodunda özellikle
 * önemlidir: "imza geçersiz" ile "kodda bug var" birbirine karışırsa,
 * geçersiz bir imza sessizce yutulabilir.
 */
export abstract class EImzaError extends Error {
  protected constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}

/* ── PDF ve ZIP ayrıştırma ────────────────────────────────────────────── */

/**
 * PDF okunamadı: yapısı bozuk ya da beklenen alan yok.
 *
 * Bir imza doğrulanırken PDF dışarıdan gelir; bozuk bir belgeyi ayırt etmek
 * çağıranın işi olduğu için bu da kütüphanenin kendi hata ağacında.
 */
export class PdfSyntaxError extends EImzaError {
  constructor(detail: string) {
    super(`PDF: ${detail}`)
  }
}

/** ZIP konteyneri okunamadı — ASiC paketleri bu biçimde taşınır. */
export class ZipSyntaxError extends EImzaError {
  constructor(detail: string) {
    super(`ZIP: ${detail}`)
  }
}

/* ── XML ayrıştırma ───────────────────────────────────────────────────── */

/** Belge iyi-biçimli değil. */
export class XmlSyntaxError extends EImzaError {
  constructor(
    /** Sorunun görüldüğü karakter konumu (0 tabanlı). */
    readonly position: number,
    detail: string,
  ) {
    super(`XML sözdizimi hatası (konum ${String(position)}): ${detail}`)
  }
}

/**
 * Belgede `<!DOCTYPE …>` bildirimi var.
 *
 * İmza doğrulayan bir kütüphanede DTD kabul etmek savunulamaz. Varlık
 * genişletme saldırıları (XXE, "milyar kahkaha") DTD üzerinden gelir; dahası
 * bir varlık, imzalanan baytlarla doğrulanan baytların farklı olmasına yol
 * açabilir — imzanın anlamını kaybettiği durum tam olarak budur.
 */
export class DoctypeNotAllowedError extends EImzaError {
  constructor() {
    super(
      'Belgede DOCTYPE bildirimi var. İmzalanan ve doğrulanan baytların aynı ' +
        'olduğunu garanti edemediği için DTD bu kütüphanede kabul edilmez.',
    )
  }
}

/** Bildirilmemiş bir ad alanı ön eki kullanılmış. */
export class UnboundPrefixError extends EImzaError {
  constructor(readonly prefix: string) {
    super(`"${prefix}" ön eki hiçbir ad alanına bağlanmamış.`)
  }
}

/** Girdi, güvenlik sınırlarından birini aştı. */
export class XmlLimitExceededError extends EImzaError {
  constructor(
    readonly limit: 'size' | 'depth',
    readonly actual: number,
    readonly maximum: number,
  ) {
    const ad = limit === 'size' ? 'Belge boyutu' : 'İç içe geçme derinliği'
    super(`${ad} sınırı aşıldı: ${String(actual)} > ${String(maximum)}.`)
  }
}

/* ── Kanonikleştirme ──────────────────────────────────────────────────── */

/** İstenen kanonikleştirme algoritması desteklenmiyor. */
export class UnsupportedCanonicalizationError extends EImzaError {
  constructor(readonly algorithm: string) {
    super(`Desteklenmeyen kanonikleştirme algoritması: ${algorithm}`)
  }
}

/* ── ASN.1 / DER ──────────────────────────────────────────────────────── */

/** DER baytları çözümlenemedi. */
export class DerParseError extends EImzaError {
  constructor(
    readonly offset: number,
    detail: string,
  ) {
    super(`DER çözümleme hatası (bayt ${String(offset)}): ${detail}`)
  }
}

/* ── Anahtar malzemesi ────────────────────────────────────────────────── */

/**
 * PKCS#12 kabı açılamadı.
 *
 * `reason` ayrımı kasıtlıdır: kullanıcıya "şifre yanlış" ile "bu dosya
 * desteklenmeyen bir algoritma kullanıyor" arasındaki farkı söylemek,
 * ikisini tek bir "yükleme başarısız" mesajında toplamaktan çok daha
 * kullanışlıdır — birincisi kullanıcının düzeltebileceği, ikincisi
 * kütüphanenin düzeltmesi gereken bir durumdur.
 */
export class Pkcs12Error extends EImzaError {
  constructor(
    readonly reason: 'password' | 'integrity' | 'unsupported' | 'malformed' | 'missing',
    detail: string,
  ) {
    super(`PKCS#12: ${detail}`)
  }
}

/* ── İmzalama ve doğrulama ────────────────────────────────────────────── */

/** İmzalama girdisi tutarsız. */
export class SigningError extends EImzaError {
  constructor(detail: string) {
    super(`İmzalama hatası: ${detail}`)
  }
}

/**
 * Doğrulama sırasında beklenmeyen bir yapı görüldü.
 *
 * Dikkat: bu sınıf "imza geçersiz" ANLAMINA GELMEZ. Geçersiz imza bir hata
 * değil, {@link SignatureVerificationResult} içinde `valid: false` olarak
 * dönen normal bir sonuçtur. Bu hata yalnızca imzanın hiç değerlendirilemediği
 * durumlarda fırlatılır — örneğin `ds:Signature` öğesi hiç yoksa.
 */
export class VerificationError extends EImzaError {
  constructor(detail: string) {
    super(`Doğrulama hatası: ${detail}`)
  }
}
