import { generateSharedKey, joinShares } from 'devolutions-crypto'
import { expect } from 'chai'
import { describe, it } from 'mocha'

describe('secretSharing', () => {
  it('should be able to retrieve the same 32 bytes shared key', () => {
    const shares: [number][] = generateSharedKey(5, 3, 32)

    const sharesGroup1: [number][] = shares.slice(0, 3)
    const sharesGroup2: [number][] = shares.slice(1, 4)
    const sharesGroup3: [number][] = shares.slice(2, 5)

    const key1: Uint8Array = joinShares(sharesGroup1)
    const key2: Uint8Array = joinShares(sharesGroup2)
    const key3: Uint8Array = joinShares(sharesGroup3)

    expect(key1).to.have.lengthOf(32)
    expect(key1).to.not.eql(new Uint8Array(32).fill(0))
    expect(key1).to.eql(key2)
    expect(key1).to.eql(key3)
  })

  it('should be able to retrieve the same 41 bytes shared key', () => {
    const shares: [number][] = generateSharedKey(5, 3, 41)

    const sharesGroup1: [number][] = shares.slice(0, 3)
    const sharesGroup2: [number][] = shares.slice(2, 5)

    const key1: Uint8Array = joinShares(sharesGroup1)
    const key2: Uint8Array = joinShares(sharesGroup2)

    expect(key1).to.have.lengthOf(41)
    expect(key1).to.not.eql(new Uint8Array(41).fill(0))
    expect(key1).to.eql(key2)
  })

  it('should throw an error if the parameters are invalid', () => {
    expect(() => generateSharedKey(3, 5, 32)).to.throw()
  })

  it('should throw an error if there is not enough shares', () => {
    const shares: [number][] = generateSharedKey(5, 3, 32)
    const sharesGroup: [number][] = shares.slice(0, 2)

    expect(() => joinShares(sharesGroup)).to.throw()
  })
})
