import assert from 'assert'
import BigInteger from 'bigi'
import createHash from 'create-hash'
import ecurve from 'ecurve'
import {Buffer} from 'safe-buffer'
import {sha256, sha512} from './hash'
import {PublicKey} from './PublicKey'
import * as keyUtils from './utils/key_utils'
import {IData} from './types'

const Point = ecurve.Point
const secp256k1 = ecurve.getCurveByName('secp256k1')

export class PrivateKey {
    static initialized = false
    static initialize() {
        if (this.initialized) {
            return
        }

        selfCheck()
        keyUtils.addEntropy(...keyUtils.cpuEntropy())
        assert(keyUtils.entropyCount >= 128, 'insufficient entropy')

        this.initialized = true
    }

    static fromHex(hex: string) {
        return PrivateKey.fromBuffer(new Buffer(hex, 'hex'))
    }

    static fromBuffer(buf: Buffer) {
        if (!Buffer.isBuffer(buf)) {
            throw new Error('Expecting parameter to be a Buffer type')
        }
        if (buf.length === 33 && buf[32] === 1) {
            // remove compression flag
            buf = buf.slice(0, -1)
        }
        if (32 !== buf.length) {
            throw new Error(`Expecting 32 bytes, instead got ${buf.length}`)
        }
        return new PrivateKey(BigInteger.fromBuffer(buf))
    }

    static fromSeed(seed: string): PrivateKey {
        if (!(typeof seed === 'string')) {
            throw new Error('seed must be of type string')
        }
        return PrivateKey.fromBuffer(sha256(seed))
    }

    static isWif(text: string): boolean {
        try {
            assert(parseKey(text).format === 'WIF')
            return true
        } catch (e) {
            return false
        }
    }

    /**
     @arg {wif|Buffer|PrivateKey} key
     @return {boolean} true if key is convertable to a private key object.
     */
    static isValid(key: IData | PrivateKey): boolean {
        try {
            new PrivateKey(key)
            return true
        } catch (e) {
            return false
        }
    }

    /** @deprecated */
    static fromWif(str: string): PrivateKey {
        console.log('PrivateKey.fromWif is deprecated, please use PrivateKey.fromString')
        return PrivateKey.fromString(str)
    }

    /**
     @arg {string} privateStr Eosio or Wallet Import Format (wif) -- a secret
     */
    static fromString(privateStr: string) {
        return parseKey(privateStr).privateKey
    }

    /**
     Create a new random private key.

     Call initialize() first to run some self-checking code and gather some CPU
     entropy.

     @arg {number} [cpuEntropyBits = 0] - additional CPU entropy, this already
     happens once so it should not be needed again.

     @return {Promise<PrivateKey>} - random private key
     */
    static randomKey(cpuEntropyBits: number = 0): PrivateKey {
        this.initialize()

        return PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({cpuEntropyBits}))
    }

    /**
     @return {Promise<PrivateKey>} for testing, does not require initialize().
     */
    static unsafeRandomKey(): PrivateKey {
        return PrivateKey.fromBuffer(keyUtils.random32ByteBuffer({safe: false}))
    }

    d: any

    constructor(d: BigInteger) {
        if (typeof d === 'string') {
            return PrivateKey.fromString(d)
        } else if (Buffer.isBuffer(d)) {
            return PrivateKey.fromBuffer(d)
        } else if (typeof d === 'object' && BigInteger.isBigInteger(d.d)) {
            return new PrivateKey(d.d)
        }

        if (!BigInteger.isBigInteger(d)) {
            throw new TypeError('Invalid private key')
        }

        this.d = d
    }


    toString(): string {
        return this.toWif()
    }

    toWif(): string {
        return keyUtils.checkEncode(
            Buffer.concat([
                new Buffer([0x80]),
                this.toBuffer()
            ]),
            'sha256x2'
        )
    }


    public_key?: PublicKey

    toPublic(): ecurve.Point {
        if (this.public_key) {
            return this.public_key
        }
        const Q = secp256k1.G.multiply(this.d)
        return this.public_key = PublicKey.fromPoint(Q)
    }

    toBuffer() {
        return this.d.toBuffer(32)
    }

    getSharedSecret(public_key: IData): Buffer {
        let KB = new PublicKey(public_key).toUncompressed().toBuffer()
        let KBP = Point.fromAffine(
            secp256k1,
            BigInteger.fromBuffer(KB.slice(1, 33)), // x
            BigInteger.fromBuffer(KB.slice(33, 65)) // y
        )
        let r = this.toBuffer()
        let P = KBP.multiply(BigInteger.fromBuffer(r))
        let S = P.affineX.toBuffer({size: 32})
        // SHA512 used in ECIES
        return sha512(S)
    }

    getChildKey(name: string): PrivateKey {
        // console.error('WARNING: getChildKey untested against eosd'); // no eosd impl yet
        const index = createHash('sha256').update(this.toBuffer()).update(name).digest()
        return new PrivateKey(index)
    }

    toHex() {
        return this.toBuffer().toString('hex')
    }

}

/**
 @typedef {string} wif - https://en.bitcoin.it/wiki/Wallet_import_format
 @typedef {string} pubkey - EOSKey..
 @typedef {ecurve.Point} Point
 */

/**
 @param {BigInteger} d
 */

/** @private */
function parseKey(privateStr: string) {
    assert.equal(typeof privateStr, 'string', 'privateStr')
    const match = privateStr.match(/^PVT_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)

    if (match === null) {
        // legacy WIF - checksum includes the version
        const versionKey = keyUtils.checkDecode(privateStr, 'sha256x2')
        const version = versionKey.readUInt8(0)
        assert.equal(0x80, version, `Expected version ${0x80}, instead got ${version}`)
        const privateKey = PrivateKey.fromBuffer(versionKey.slice(1))
        const keyType = 'K1'
        const format = 'WIF'
        return {privateKey, format, keyType}
    }

    assert(match.length === 3, 'Expecting private key like: PVT_K1_base58privateKey..')
    const [, keyType, keyString] = match
    assert.equal(keyType, 'K1', 'K1 private key expected')
    const privateKey = PrivateKey.fromBuffer(keyUtils.checkDecode(keyString, keyType))
    return {privateKey, format: 'PVT', keyType}
}

function selfCheck() {
    const pvt = new PrivateKey(sha256(''))

    const pvtError = 'key comparison test failed on a known private key'
    assert.equal(pvt.toWif(), '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', pvtError)
    assert.equal(pvt.toString(), '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', pvtError)
    // assert.equal(pvt.toString(), 'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd', pvtError)

    const pub = pvt.toPublic()
    const pubError = 'pubkey string comparison test failed on a known public key'
    assert.equal(pub.toString(), 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', pubError)
    // assert.equal(pub.toString(), 'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX', pubError)
    // assert.equal(pub.toStringLegacy(), 'EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM', pubError)

    doesNotThrow(() => PrivateKey.fromString(pvt.toWif()), 'converting known wif from string')
    doesNotThrow(() => PrivateKey.fromString(pvt.toString()), 'converting known pvt from string')
    doesNotThrow(() => PublicKey.fromString(pub.toString()), 'converting known public key from string')
    // doesNotThrow(() => PublicKey.fromString(pub.toStringLegacy()), 'converting known public key from string')
}

const doesNotThrow = (cb: () => void, msg: string) => {
    try {
        cb()
    } catch (error) {
        error.message = `${msg} ==> ${error.message}`
        throw error
    }
}
