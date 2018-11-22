import assert from 'assert'
import ecurve from 'ecurve'
import {Buffer} from 'safe-buffer'
import * as keyUtils from './utils/key_utils'
import {IData} from './types'

const secp256k1 = ecurve.getCurveByName('secp256k1')

const getPoint = {
    fromBuffer: (buffer: Buffer): ecurve.Point => ecurve.Point.decodeFrom(secp256k1, buffer),
    fromBinary: (bin: string): ecurve.Point => getPoint.fromBuffer(Buffer.from(bin, 'binary')),
    fromHexString: (hex: string): ecurve.Point => getPoint.fromBuffer(Buffer.from(hex, 'hex')),
    fromString: (public_key: string, pubkey_prefix: string = 'EOS'): ecurve.Point => {
        assert.equal(typeof public_key, 'string', 'public_key')
        const match = public_key.match(/^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
        if (match === null) {
            // legacy
            const prefix_match = new RegExp(`^${pubkey_prefix}`)
            if (prefix_match.test(public_key)) {
                public_key = public_key.substring(pubkey_prefix.length)
            }
            return getPoint.fromBuffer(keyUtils.checkDecode(public_key))
        } else {
            assert(match.length === 3, 'Expecting public key like: PUB_K1_base58pubkey..')
            const [, keyType, keyString] = match
            assert.equal(keyType, 'K1', 'K1 private key expected')
            return getPoint.fromBuffer(keyUtils.checkDecode(keyString, keyType))
        }
    },
    fromGeneric: (generic: Buffer | string | ecurve.Point, pubkey_prefix: string): ecurve.Point => {
        switch (true) {
            case typeof generic === 'string':
                return getPoint.fromString(generic, pubkey_prefix)
            case Buffer.isBuffer(generic):
                return getPoint.fromBuffer(generic)
            case typeof generic === 'object' && generic.Q:
                return getPoint.fromGeneric(generic.Q, pubkey_prefix)
            case generic.x && generic.y && generic.z && generic.compressed !== undefined:
                return (generic as ecurve.Point)
            default:
                throw new Error('unexpected generic value')
        }
    }
}

export class PublicKey {
    static isValid(pubkey: IData | PublicKey | ecurve.Point, pubkey_prefix: string = 'EOS'): boolean {
        try {
            new this(pubkey, pubkey_prefix)
            return true
        } catch (e) {
            return false
        }
    }

    static fromBinary(bin: string): PublicKey {
        return new this(getPoint.fromBinary(bin))
    }

    static fromBuffer(buffer: Buffer): PublicKey {
        return new this(getPoint.fromBuffer(buffer))
    }

    static fromPoint(point: ecurve.Point): PublicKey {
        return new this(point)
    }

    static fromString(public_key: string, pubkey_prefix = 'EOS'): null | PublicKey {
        try {
            return new this(getPoint.fromString(public_key, pubkey_prefix))
        } catch (e) {
            return null
        }
    }

    static fromStringOrThrow(public_key: string, pubkey_prefix: string = 'EOS'): PublicKey {
        return new this(getPoint.fromString(public_key, pubkey_prefix))
    }

    static fromHex(hex: string) {
        return new this(getPoint.fromHexString(hex))
    }

    Q: ecurve.Point

    constructor(Q: IData | ecurve.Point | { Q: ecurve.Point }, pubkey_prefix = 'EOS') {
        this.Q = getPoint.fromGeneric(Q, pubkey_prefix)
    }

    toString(pubkey_prefix = 'EOS') {
        return `${pubkey_prefix}${keyUtils.checkEncode(this.toBuffer())}`
    }

    toHex() {
        return this.toBuffer().toString('hex')
    }

    toBuffer(compressed = this.Q.compressed) {
        return this.Q.getEncoded(compressed)
    }

    toUncompressed() {
        const buf = this.Q.getEncoded(false)
        const point = ecurve.Point.decodeFrom(secp256k1, buf)
        return PublicKey.fromPoint(point)
    }
}
