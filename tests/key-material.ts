import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * Test için anahtar malzemesi üretir.
 *
 * Anahtarlar **depoda tutulmaz**, her koşuda geçici dizinde üretilir. İki
 * nedeni var: özel anahtar bir kez depoya girerse geçmişten güvenilir biçimde
 * silinemez, ve kapların algoritma çeşitliliği ancak onları gerçekten
 * üreterek elde edilir.
 *
 * İki farklı OpenSSL kullanılır — sürüm farkı burada tesadüf değil, testin
 * konusu:
 * - **LibreSSL** (macOS sistemi) hâlâ `pbeWithSHAAnd40BitRC2-CBC` yazar; eski
 *   Java ve Windows araçlarının ürettiği kapların birebir aynısı.
 * - **OpenSSL 3** PBES2 + AES-256 yazar; bugünün varsayılanı.
 *
 * Bir kütüphanenin ikisini birden açabildiğini, ancak ikisini birden üreterek
 * gösterebilirsiniz.
 */

/** Üretilen bir anahtar kabı. */
export interface KeyFixture {
  /** `.p12` dosyasının içeriği. */
  readonly p12: Uint8Array
  /** Kap parolası. */
  readonly password: string
  /** Uç sertifika (PEM). */
  readonly certificatePem: string
  /** İnsan tarafından okunabilir açıklama — test adlarında kullanılır. */
  readonly label: string
}

/** Tüm üretilen malzeme. */
export interface KeyMaterial {
  /** OpenSSL 3 varsayılanı: PBES2 + AES-256-CBC, RSA anahtar. */
  readonly modernRsa: KeyFixture
  /** LibreSSL varsayılanı: sertifikalar RC2-40, anahtar 3DES. */
  readonly legacyRc2: KeyFixture
  /** EC (P-256) anahtar taşıyan modern kap. */
  readonly modernEc: KeyFixture
  /** Ara sertifika ve kökle birlikte üç halkalı zincir. */
  readonly withChain: KeyFixture
  /** Parolasız kap — boş parola kodlaması belirsizliğini sınar. */
  readonly emptyPassword: KeyFixture
  /** Çevrimdışı zaman damgası otoritesi. */
  readonly tsa: TsaFixture
  /** Çevrimdışı OCSP yanıtlayıcısı. */
  readonly ocsp: OcspFixture
  /** `withChain` kabındaki uç sertifikayı düzenleyen ara CA (DER). */
  readonly intermediateCertificate: Uint8Array
  /** Kök CA (DER). */
  readonly rootCertificate: Uint8Array
}

/**
 * Çevrimdışı bir OCSP yanıtlayıcısı.
 *
 * `openssl ocsp -index …` gerçek, imzalı bir yanıt üretebiliyor — ağ
 * gerekmiyor. Zaman damgasında olduğu gibi iki yön birden sınanabiliyor:
 * ürettiğimiz isteği OpenSSL okuyabiliyor mu, ve OpenSSL'in ürettiği
 * yanıtı biz doğrulayabiliyor muyuz.
 */
export interface OcspFixture {
  /** Bir `OCSPRequest` için imzalı `OCSPResponse` üretir. */
  readonly respond: (request: Uint8Array, revoked?: boolean) => Uint8Array
  /** Yanıtları imzalayan sertifika (DER) — burada ara CA'nın kendisi. */
  readonly responderCertificate: Uint8Array
}

/**
 * Çevrimdışı bir RFC 3161 zaman damgası otoritesi.
 *
 * `openssl ts -reply` gerçek bir jeton üretebiliyor — ağ gerekmiyor. Bu,
 * zaman damgası kodunu iki yönde birden sınamayı mümkün kılıyor: bizim
 * ürettiğimiz isteği OpenSSL kabul ediyor mu, ve OpenSSL'in ürettiği jetonu
 * biz doğrulayabiliyor muyuz.
 */
export interface TsaFixture {
  /** Bir `TimeStampReq` için `TimeStampResp` üretir. */
  readonly issue: (request: Uint8Array) => Uint8Array
  /** TSA sertifikası (DER). */
  readonly certificate: Uint8Array
  /** TSA'yı imzalayan kök (DER). */
  readonly rootCertificate: Uint8Array
  /** TSA'nın varsayılan politika OID'i. */
  readonly policyOid: string
}

const MODERN =
  ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find((p) =>
    existsSync(p),
  ) ?? 'openssl'
const LEGACY = '/usr/bin/openssl'

/** Malzemenin üretilebilir olup olmadığını söyler. */
export const canGenerateKeyMaterial = (): boolean => probe(MODERN) !== undefined

/** LibreSSL ayrı bir çalıştırılabilirse eski biçim de üretilebilir. */
export const hasLegacyOpenssl = (probe(LEGACY) ?? '').includes('LibreSSL')

/** Bir OpenSSL çalıştırılabilirinin sürüm dizesini döndürür; yoksa `undefined`. */
function probe(binary: string): string | undefined {
  try {
    return execFileSync(binary, ['version'], { encoding: 'utf8' })
  } catch {
    return undefined
  }
}

let cached: KeyMaterial | undefined

/**
 * Anahtar malzemesini üretir; aynı süreç içinde bir kez.
 *
 * @returns Üretilmiş kaplar
 */
export const keyMaterial = (): KeyMaterial => {
  if (cached !== undefined) return cached

  const dir = mkdtempSync(join(tmpdir(), 'e-imza-keys-'))
  const at = (name: string): string => join(dir, name)
  const run = (binary: string, args: readonly string[]): void => {
    execFileSync(binary, [...args], { stdio: ['ignore', 'ignore', 'pipe'] })
  }
  const password = 'test-parola'

  // Kök CA.
  // prettier-ignore
  run(MODERN, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-keyout', at('ca.key'), '-out', at('ca.crt'), '-days', '3650',
    '-subj', '/C=TR/O=e-imza Test/CN=e-imza Test Kok CA'])

  // Ara CA. `basicConstraints CA:TRUE` olmadan üretilen ara sertifika zincir
  // kurmaz — uzantı bu yüzden açıkça yazılıyor.
  writeFileSync(
    at('ara.ext'),
    'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n',
  )
  // prettier-ignore
  run(MODERN, ['req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', at('ara.key'), '-out', at('ara.csr'),
    '-subj', '/C=TR/O=e-imza Test/CN=e-imza Test Ara CA'])
  // prettier-ignore
  run(MODERN, ['x509', '-req', '-in', at('ara.csr'), '-sha256', '-days', '1825',
    '-CA', at('ca.crt'), '-CAkey', at('ca.key'), '-CAcreateserial',
    '-extfile', at('ara.ext'), '-out', at('ara.crt')])

  // Uç sertifika — ara CA imzalar.
  // prettier-ignore
  run(MODERN, ['req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', at('uc.key'), '-out', at('uc.csr'),
    '-subj', '/C=TR/O=Ornek Sirket A.S./CN=Ornek Mali Muhur/serialNumber=1234567890'])
  // prettier-ignore
  run(MODERN, ['x509', '-req', '-in', at('uc.csr'), '-sha256', '-days', '825',
    '-CA', at('ara.crt'), '-CAkey', at('ara.key'), '-CAcreateserial',
    '-out', at('uc.crt')])

  // EC anahtar, kendi kendini imzalar.
  // prettier-ignore
  run(MODERN, ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
    'ec_paramgen_curve:prime256v1', '-nodes', '-sha256', '-days', '825',
    '-keyout', at('ec.key'), '-out', at('ec.crt'),
    '-subj', '/C=TR/O=Ornek Sirket A.S./CN=Ornek EC Muhur'])

  // `-chain` bir güven deposu ister; buradaki testin konusu doğrulama değil,
  // kapta birden çok sertifika bulunması. Zincir doğrudan gömülüyor.
  writeFileSync(
    at('zincir.pem'),
    readFileSync(at('ara.crt'), 'utf8') + readFileSync(at('ca.crt'), 'utf8'),
  )

  const pack = (
    binary: string,
    output: string,
    args: readonly string[],
    pass: string,
  ): Uint8Array => {
    run(binary, ['pkcs12', '-export', '-out', at(output), '-passout', `pass:${pass}`, ...args])
    return new Uint8Array(readFileSync(at(output)))
  }

  const ucPem = readFileSync(at('uc.crt'), 'utf8')
  // prettier-ignore
  const leafArgs = ['-inkey', at('uc.key'), '-in', at('uc.crt')]

  const modernRsa: KeyFixture = {
    p12: pack(MODERN, 'modern.p12', [...leafArgs, '-name', 'Ornek Mali Muhur'], password),
    password,
    certificatePem: ucPem,
    label: 'OpenSSL 3 — PBES2 + AES-256',
  }

  cached = {
    modernRsa,
    legacyRc2: hasLegacyOpenssl
      ? {
          p12: pack(LEGACY, 'legacy.p12', leafArgs, password),
          password,
          certificatePem: ucPem,
          label: 'LibreSSL — pbeWithSHAAnd40BitRC2-CBC',
        }
      : modernRsa,
    modernEc: {
      p12: pack(MODERN, 'ec.p12', ['-inkey', at('ec.key'), '-in', at('ec.crt')], password),
      password,
      certificatePem: readFileSync(at('ec.crt'), 'utf8'),
      label: 'OpenSSL 3 — EC P-256',
    },
    withChain: {
      p12: pack(MODERN, 'zincir.p12', [...leafArgs, '-certfile', at('zincir.pem')], password),
      password,
      certificatePem: ucPem,
      label: 'OpenSSL 3 — uç + ara + kök',
    },
    emptyPassword: {
      p12: pack(MODERN, 'bos.p12', leafArgs, ''),
      password: '',
      certificatePem: ucPem,
      label: 'OpenSSL 3 — parolasız',
    },
    tsa: buildTsa(dir, at, run),
    ocsp: buildOcsp(dir, at, run),
    intermediateCertificate: (() => {
      run(MODERN, ['x509', '-in', at('ara.crt'), '-outform', 'DER', '-out', at('ara.der')])
      return new Uint8Array(readFileSync(at('ara.der')))
    })(),
    rootCertificate: (() => {
      run(MODERN, ['x509', '-in', at('ca.crt'), '-outform', 'DER', '-out', at('ca-kok.der')])
      return new Uint8Array(readFileSync(at('ca-kok.der')))
    })(),
  }
  return cached
}

/**
 * Çevrimdışı bir OCSP yanıtlayıcısı kurar.
 *
 * Yanıtları ARA CA imzalıyor — uç sertifikayı düzenleyen de o olduğu için
 * bu, RFC 6960'ın "yanıtlayıcı düzenleyenin kendisidir" durumu. Yetki
 * denetimi bu kütüphanenin kapsamı dışında olduğu için ayrı bir
 * `id-kp-OCSPSigning` sertifikası kurmaya gerek yok.
 */
const buildOcsp = (
  dir: string,
  at: (name: string) => string,
  run: (binary: string, args: readonly string[]) => void,
): OcspFixture => {
  // OpenSSL'in dizin dosyası: durum, son kullanma, iptal tarihi, seri, dosya, konu.
  const serial = execFileSync(MODERN, ['x509', '-in', at('uc.crt'), '-noout', '-serial'], {
    encoding: 'utf8',
  })
    .trim()
    .split('=')[1]
  const subject = '/C=TR/O=Ornek Sirket A.S./CN=Ornek Mali Muhur/serialNumber=1234567890'
  writeFileSync(
    at('index-gecerli.txt'),
    `V\t300101000000Z\t\t${serial ?? ''}\tunknown\t${subject}\n`,
  )
  writeFileSync(
    at('index-iptal.txt'),
    `R\t300101000000Z\t250101000000Z,keyCompromise\t${serial ?? ''}\tunknown\t${subject}\n`,
  )
  run(MODERN, ['x509', '-in', at('ara.crt'), '-outform', 'DER', '-out', at('ara-ocsp.der')])

  let counter = 0
  return {
    respond: (request: Uint8Array, revoked = false): Uint8Array => {
      counter += 1
      const query = join(dir, `ocsp-req-${String(counter)}.der`)
      const reply = join(dir, `ocsp-resp-${String(counter)}.der`)
      writeFileSync(query, request)
      // prettier-ignore
      run(MODERN, ['ocsp',
        '-index', at(revoked ? 'index-iptal.txt' : 'index-gecerli.txt'),
        '-CA', at('ara.crt'), '-rsigner', at('ara.crt'), '-rkey', at('ara.key'),
        '-reqin', query, '-respout', reply, '-nmin', '60'])
      return new Uint8Array(readFileSync(reply))
    },
    responderCertificate: new Uint8Array(readFileSync(at('ara-ocsp.der'))),
  }
}

/** TSA politika OID'i — testin kendi ayırdığı, kayıtlı olmayan bir dal. */
const TSA_POLICY_OID = '1.3.6.1.4.1.99999.1.1'

/** Çevrimdışı bir zaman damgası otoritesi kurar. */
const buildTsa = (
  dir: string,
  at: (name: string) => string,
  run: (binary: string, args: readonly string[]) => void,
): TsaFixture => {
  // TSA sertifikası `timeStamping` genişletilmiş anahtar kullanımı TAŞIMALI;
  // taşımayan bir sertifikayla üretilen jetonu uyumlu doğrulayıcılar
  // reddeder.
  writeFileSync(
    at('tsa.ext'),
    'basicConstraints=critical,CA:FALSE\n' +
      'keyUsage=critical,digitalSignature\n' +
      'extendedKeyUsage=critical,timeStamping\n',
  )
  // prettier-ignore
  run(MODERN, ['req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', at('tsa.key'), '-out', at('tsa.csr'),
    '-subj', '/C=TR/O=e-imza Test/CN=e-imza Test TSA'])
  // prettier-ignore
  run(MODERN, ['x509', '-req', '-in', at('tsa.csr'), '-sha256', '-days', '1825',
    '-CA', at('ca.crt'), '-CAkey', at('ca.key'), '-CAcreateserial',
    '-extfile', at('tsa.ext'), '-out', at('tsa.crt')])

  writeFileSync(
    at('tsa.cnf'),
    [
      '[ tsa ]',
      'default_tsa = tsa_config',
      '[ tsa_config ]',
      `serial = ${at('tsa.serial')}`,
      'crypto_device = builtin',
      `signer_cert = ${at('tsa.crt')}`,
      `certs = ${at('ca.crt')}`,
      `signer_key = ${at('tsa.key')}`,
      'signer_digest = sha256',
      `default_policy = ${TSA_POLICY_OID}`,
      'digests = sha256, sha384, sha512',
      'accuracy = secs:1',
      'clock_precision_digits = 0',
      'ordering = yes',
      'tsa_name = yes',
      'ess_cert_id_alg = sha256',
      '',
    ].join('\n'),
  )
  writeFileSync(at('tsa.serial'), '01\n')

  const toDer = (pem: string, out: string): Uint8Array => {
    run(MODERN, ['x509', '-in', at(pem), '-outform', 'DER', '-out', at(out)])
    return new Uint8Array(readFileSync(at(out)))
  }

  let counter = 0
  return {
    issue: (request: Uint8Array): Uint8Array => {
      counter += 1
      const query = join(dir, `req-${String(counter)}.tsq`)
      const reply = join(dir, `resp-${String(counter)}.tsr`)
      writeFileSync(query, request)
      // prettier-ignore
      run(MODERN, ['ts', '-reply', '-config', at('tsa.cnf'),
        '-queryfile', query, '-out', reply])
      return new Uint8Array(readFileSync(reply))
    },
    certificate: toDer('tsa.crt', 'tsa.der'),
    rootCertificate: toDer('ca.crt', 'ca.der'),
    policyOid: TSA_POLICY_OID,
  }
}
