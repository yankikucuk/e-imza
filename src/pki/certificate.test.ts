import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

import { derNull, derSequence } from '../asn1/der.js'
import { DerParseError } from '../core/errors.js'

import { readCertificate } from './certificate.js'

const OPENSSL =
  ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/local/opt/openssl@3/bin/openssl'].find((path) =>
    existsSync(path),
  ) ?? 'openssl'

const available = ((): boolean => {
  try {
    execFileSync(OPENSSL, ['version'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

const directory = mkdtempSync(join(tmpdir(), 'e-imza-cert-test-'))
afterAll(() => {
  rmSync(directory, { recursive: true, force: true })
})

let counter = 0
/** Verilen konu adıyla bir sertifika üretir ve DER olarak döner. */
const make = (subject: string, algorithm: 'rsa' | 'ec' = 'rsa'): Uint8Array => {
  counter += 1
  const der = join(directory, `c${String(counter)}.der`)
  const key = join(directory, `k${String(counter)}.pem`)
  // prettier-ignore
  const keyArgs = algorithm === 'rsa'
    ? ['-newkey', 'rsa:2048']
    : ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1']
  // prettier-ignore
  execFileSync(OPENSSL, ['req', '-x509', ...keyArgs, '-nodes', '-sha256', '-days', '365',
    '-keyout', key, '-outform', 'DER', '-out', der, '-subj', subject, '-utf8'])
  return new Uint8Array(readFileSync(der))
}

describe.skipIf(!available)('sertifika okuma', () => {
  it('temel alanları çıkarır', () => {
    const info = readCertificate(make('/C=TR/O=Ornek A.S./CN=Ornek Muhur'))
    expect(info.subjectName).toBe('CN=Ornek Muhur,O=Ornek A.S.,C=TR')
    expect(info.issuerName).toBe(info.subjectName)
    expect(info.serialNumber).toBeGreaterThan(0n)
    expect(info.keyAlgorithm).toBe('rsa')
    expect(info.notAfter.getTime()).toBeGreaterThan(info.notBefore.getTime())
  })

  it('EC anahtarı tanır', () => {
    expect(readCertificate(make('/CN=EC', 'ec')).keyAlgorithm).toBe('ec')
  })

  /**
   * Türkiye'de mali mühür ve NES sertifikalarında VKN ya da TCKN, konudaki
   * `serialNumber` özniteliğinde (OID 2.5.4.5) taşınır. Sertifikanın SERİ
   * NUMARASI ile karıştırılmamalı — ikisi ayrı alanlar.
   */
  it('konudaki serialNumber özniteliğini ayrıca verir', () => {
    const info = readCertificate(make('/C=TR/CN=Muhur/serialNumber=1234567890'))
    expect(info.subjectSerialNumber).toBe('1234567890')
    expect(info.serialNumber).not.toBe(1234567890n)
  })

  it('serialNumber yoksa alan hiç bulunmaz', () => {
    expect(readCertificate(make('/CN=Yok')).subjectSerialNumber).toBeUndefined()
  })

  it('Türkçe karakterler korunur', () => {
    const info = readCertificate(make('/C=TR/O=Şirket Ünvanı/CN=Ğüşıöç'))
    expect(info.subjectName).toContain('Ğüşıöç')
    expect(info.subjectName).toContain('Şirket Ünvanı')
  })

  /** RFC 4514 §2.4: virgül kaçırılır; kaçırılmazsa dize iki bileşen okunur. */
  it('değerdeki virgül kaçırılır', () => {
    expect(readCertificate(make('/O=Test/CN=Ornek, A.S.')).subjectName).toBe(
      'CN=Ornek\\, A.S.,O=Test',
    )
  })

  /** Sondaki boşluk da kaçırılır; yoksa yeniden okunduğunda kaybolur. */
  it('sondaki boşluk kaçırılır', () => {
    expect(readCertificate(make('/CN=Ad ')).subjectName).toBe('CN=Ad\\ ')
  })

  /**
   * Çok değerli RDN bileşenleri `+` ile birleşir. OpenSSL'in `-subj`
   * ayrıştırıcısı `+` işaretini tam olarak bu amaçla kullanır.
   */
  it('çok değerli RDN + ile birleşir', () => {
    const info = readCertificate(make('/C=TR/CN=Ad+O=Firma'))
    expect(info.subjectName).toMatch(/(CN=Ad\+O=Firma|O=Firma\+CN=Ad)/)
  })

  /**
   * Tanınmayan öznitelikler noktalı OID ve `#onaltılık` ham değerle yazılır
   * — RFC 4514'ün kendi kuralı. Tahmin etmek, yeniden okunduğunda farklı
   * ayrıştırılacak bir dize üretmek olurdu.
   */
  it('tanınmayan öznitelik OID ve ham değerle yazılır', () => {
    const info = readCertificate(make('/CN=X/businessCategory=Ticaret'))
    expect(info.subjectName).toMatch(/2\.5\.4\.15=#[0-9a-f]+/)
  })

  it('bilinen kısa adlar kullanılır', () => {
    const info = readCertificate(make('/C=TR/ST=Marmara/L=Istanbul/O=Firma/OU=Birim/CN=Ad'))
    expect(info.subjectName).toBe('CN=Ad,OU=Birim,O=Firma,L=Istanbul,ST=Marmara,C=TR')
  })
})

describe('bozuk girdi', () => {
  it('X.509 olmayan yapı reddedilir', () => {
    expect(() => readCertificate(derSequence(derNull()))).toThrow(DerParseError)
  })

  it('boş SEQUENCE reddedilir', () => {
    expect(() => readCertificate(derSequence())).toThrow(DerParseError)
  })
})
