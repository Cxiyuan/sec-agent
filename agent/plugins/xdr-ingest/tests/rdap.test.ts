import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { normalizeDomain, registrableDomain } from '../src/rdap.ts'

test('rdap: 域名归一化', () => {
  assert.equal(normalizeDomain('https://Foo.Example.COM./path?q=1'), 'foo.example.com')
  assert.equal(normalizeDomain('aafd...v.smtcdns.com:53'), 'aafd...v.smtcdns.com')
  assert.equal(normalizeDomain(''), '')
})

test('rdap: 可注册主域取父域', () => {
  assert.equal(registrableDomain('aafd.v.smtcdns.com'), 'smtcdns.com')
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk')
  assert.equal(registrableDomain('minerva.devices.a2z.com'), 'a2z.com')
})
