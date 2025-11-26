import { generateSharedKey, joinShares } from 'devolutions-crypto'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'

describe('secretSharing', () => {
  test('should be able to retrieve the same 32 bytes shared key', () => {
    const shares: Uint8Array[] = generateSharedKey(5, 3, 32)

    const sharesGroup1: Uint8Array[] = shares.slice(0, 3)
    const sharesGroup2: Uint8Array[] = shares.slice(1, 4)
    const sharesGroup3: Uint8Array[] = shares.slice(2, 5)

    const key1: Uint8Array = joinShares(sharesGroup1)
    const key2: Uint8Array = joinShares(sharesGroup2)
    const key3: Uint8Array = joinShares(sharesGroup3)

    assert.strictEqual(key1.length, 32)
    assert.notDeepStrictEqual(key1, new Uint8Array(32))
    assert.deepStrictEqual(key1, key2)
    assert.deepStrictEqual(key1, key3)
  })

  test('should be able to retrieve the same 41 bytes shared key', () => {
    const shares: Uint8Array[] = generateSharedKey(5, 3, 41)

    const sharesGroup1: Uint8Array[] = shares.slice(0, 3)
    const sharesGroup2: Uint8Array[] = shares.slice(2, 5)

    const key1: Uint8Array = joinShares(sharesGroup1)
    const key2: Uint8Array = joinShares(sharesGroup2)

    assert.strictEqual(key1.length, 41)
    assert.notDeepStrictEqual(key1, new Uint8Array(41))
    assert.deepStrictEqual(key1, key2)
  })

  test('should throw an error if the parameters are invalid', () => {
    assert.throws(() => generateSharedKey(3, 5, 32))
  })

  test('should throw an error if there is not enough shares', () => {
    const shares: Uint8Array[] = generateSharedKey(5, 3, 32)
    const sharesGroup: Uint8Array[] = shares.slice(0, 2)

    assert.throws(() => joinShares(sharesGroup))
  })
})
