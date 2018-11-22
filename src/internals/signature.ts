import assert from 'assert'
import BigInteger from 'bigi'
import {getCurveByName} from 'ecurve'
import {Buffer} from 'safe-buffer'
import {ECSignature} from './ECSignature'
import * as hash from './hash'
import {PrivateKey} from './PrivateKey'
import {PublicKey} from './PublicKey'
import {IData} from './types'
import * as ecdsa from './utils/ecdsa'
import * as keyUtils from './utils/key_utils'

const curve = getCurveByName('secp256k1')

export class Signature {
    static sign(data: IData, privateKey: IData | PrivateKey, encoding = 'utf8'): Signature {
        if (typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        return Signature.signHash(hash.sha256(data), privateKey)
    }

    static signHash(dataSha256: IData, privateKey: IData | PrivateKey, encoding = 'hex'): Signature {
        if (typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }

        if (dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
            throw new Error('dataSha256: 32 byte buffer requred')

        privateKey = new PrivateKey(privateKey)

        assert(privateKey, 'privateKey required')

        let der: Buffer
        let ecsignature: ECSignature
        let lenR: number
        let lenS: number
        let e = BigInteger.fromBuffer(dataSha256)
        let i: number
        let nonce: number = 0
        while (true) {
            ecsignature = ecdsa.sign(curve, dataSha256, privateKey.d, nonce++)
            der = ecsignature.toDER()
            lenR = der[3]
            lenS = der[5 + lenR]
            if (lenR === 32 && lenS === 32) {
                i = ecdsa.calcPubKeyRecoveryParam(curve, e, ecsignature, privateKey.toPublic().Q)
                i += 4  // compressed
                i += 27 // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
                break
            }
            if (nonce % 10 === 0) {
                console.log(`WARN: ${nonce} attempts to find canonical signature`)
            }
        }
        return new Signature(ecsignature.r, ecsignature.s, i)
    }

    static fromBuffer(buf: Buffer) {
        let i
        let r
        let s
        assert(Buffer.isBuffer(buf), 'Buffer is required')
        assert.equal(buf.length, 65, 'Invalid signature length')
        i = buf.readUInt8(0)
        assert.equal(i - 27, i - 27 & 7, 'Invalid signature parameter')
        r = BigInteger.fromBuffer(buf.slice(1, 33))
        s = BigInteger.fromBuffer(buf.slice(33))
        return new Signature(r, s, i)
    }

    static fromHex(hex: string): Signature {
        return Signature.fromBuffer(Buffer.from(hex, 'hex'))
    }

    static fromString(signature: string): null | Signature {
        try {
            return Signature.fromStringOrThrow(signature)
        } catch (e) {
            return null
        }
    }

    static fromStringOrThrow(signature: string): Signature {
        assert.equal(typeof signature, 'string', 'signature')
        const match = signature.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
        assert(match != null && match.length === 3, 'Expecting signature like: SIG_K1_base58signature..')
        const [, keyType, keyString] = match
        assert.equal(keyType, 'K1', 'K1 signature expected')
        return Signature.fromBuffer(keyUtils.checkDecode(keyString, keyType))
    }

    static from(o: IData | Signature): Signature {
        if (!o) {
            throw new TypeError('signature should be a hex string or buffer')
        } else if (o instanceof Signature) {
            return o
        } else if (typeof o === 'string') {
            return o.length === 130
                ? Signature.fromHex(o)
                : Signature.fromStringOrThrow(o)
        } else if (Buffer.isBuffer(o)) {
            return Signature.fromBuffer(o)
        } else {
            throw new TypeError('signature should be a hex string or buffer')
        }
    }

    r: BigInteger
    s: BigInteger
    i: number

    constructor(r: BigInteger, s: BigInteger, i: number) {
        assert.equal(r != null, true, 'Missing parameter')
        assert.equal(s != null, true, 'Missing parameter')
        assert.equal(i != null, true, 'Missing parameter')
        this.r = r
        this.s = s
        this.i = i
    }

    signatureCache?: string

    toString(): string {
        if (this.signatureCache) {
            return this.signatureCache
        }
        return this.signatureCache = `SIG_K1_${keyUtils.checkEncode(this.toBuffer(), 'K1')}`
    }


    toHex(): string {
        return this.toBuffer().toString('hex')
    }


    verify(data: IData, pubkey: IData | PublicKey, encoding = 'utf8') {
        if (typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)
        return this.verifyHash(data, pubkey)
    }

    verifyHash(dataSha256: IData, pubkey: IData | PublicKey, encoding = 'hex') {
        if (typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if (dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
            throw new Error('dataSha256: 32 bytes required')

        const publicKey = new PublicKey(pubkey)
        assert(publicKey, 'pubkey required')

        return ecdsa.verify(
            curve, dataSha256,
            {r: this.r, s: this.s},
            publicKey.Q
        )
    }

    /** @deprecated */
    verifyHex(hex: IData, pubkey: IData | PublicKey): boolean {
        console.log('Deprecated: use verify(data, pubkey, "hex")')

        return this.verify(hex, pubkey, 'hex')
    }

    recover(data: IData, encoding = 'utf8'): PublicKey {
        if (typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)

        return this.recoverHash(data)
    }

    recoverHash(dataSha256: IData, encoding = 'hex'): PublicKey {
        if (typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if (dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256)) {
            throw new Error('dataSha256: 32 byte String or buffer requred')
        }

        const e = BigInteger.fromBuffer(dataSha256)
        let i2 = this.i
        i2 -= 27
        i2 = i2 & 3
        const Q = ecdsa.recoverPubKey(curve, e, {r: this.r, s: this.s, i: this.i}, i2)
        return PublicKey.fromPoint(Q)
    }

    toBuffer(): Buffer {
        let buf
        buf = new Buffer(65)
        buf.writeUInt8(this.i, 0)
        this.r.toBuffer(32).copy(buf, 1)
        this.s.toBuffer(32).copy(buf, 33)
        return buf
    }
}
