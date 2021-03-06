import assert from 'assert'
import BigInteger from 'bigi'
import {Buffer} from 'safe-buffer'
import enforceType from './utils/enforce'

export class ECSignature {
    static parseCompact(buffer: Buffer): { compressed: boolean, i: number, signature: ECSignature } {
        assert.equal(buffer.length, 65, 'Invalid signature length')
        let i = buffer.readUInt8(0) - 27

        // At most 3 bits
        assert.equal(i, i & 7, 'Invalid signature parameter')
        const compressed = !!(i & 4)

        // Recovery param only
        i = i & 3

        const r = BigInteger.fromBuffer(buffer.slice(1, 33))
        const s = BigInteger.fromBuffer(buffer.slice(33))

        return {
            compressed,
            i,
            signature: new ECSignature(r, s)
        }
    }

    static fromDER(buffer: Buffer) {
        assert.equal(buffer.readUInt8(0), 0x30, 'Not a DER sequence')
        assert.equal(buffer.readUInt8(1), buffer.length - 2, 'Invalid sequence length')
        assert.equal(buffer.readUInt8(2), 0x02, 'Expected a DER integer')

        const rLen = buffer.readUInt8(3)
        assert(rLen > 0, 'R length is zero')

        let offset = 4 + rLen
        assert.equal(buffer.readUInt8(offset), 0x02, 'Expected a DER integer (2)')

        const sLen = buffer.readUInt8(offset + 1)
        assert(sLen > 0, 'S length is zero')

        const rB = buffer.slice(4, offset)
        const sB = buffer.slice(offset + 2)
        offset += 2 + sLen

        if (rLen > 1 && rB.readUInt8(0) === 0x00) {
            assert(rB.readUInt8(1) & 0x80, 'R value excessively padded')
        }

        if (sLen > 1 && sB.readUInt8(0) === 0x00) {
            assert(sB.readUInt8(1) & 0x80, 'S value excessively padded')
        }

        assert.equal(offset, buffer.length, 'Invalid DER encoding')
        const r = BigInteger.fromDERInteger(rB)
        const s = BigInteger.fromDERInteger(sB)

        assert(r.signum() >= 0, 'R value is negative')
        assert(s.signum() >= 0, 'S value is negative')

        return new ECSignature(r, s)
    }

    // FIXME: 0x00, 0x04, 0x80 are SIGHASH_* boundary constants, importing Transaction causes a circular dependency
    static parseScriptSignature(buffer: Buffer): { signature: ECSignature, hashType: number } {
        const hashType = buffer.readUInt8(buffer.length - 1)
        const hashTypeMod = hashType & ~0x80

        assert(hashTypeMod > 0x00 && hashTypeMod < 0x04, 'Invalid hashType')

        return {
            signature: ECSignature.fromDER(buffer.slice(0, -1)),
            hashType
        }
    }


    r: BigInteger
    s: BigInteger

    constructor(r: BigInteger, s: BigInteger) {
        enforceType(BigInteger, r)
        enforceType(BigInteger, s)

        this.r = r
        this.s = s
    }

    toCompact(i: number, compressed: boolean) {
        if (compressed) i += 4
        i += 27

        const buffer = new Buffer(65)
        buffer.writeUInt8(i, 0)

        this.r.toBuffer(32).copy(buffer, 1)
        this.s.toBuffer(32).copy(buffer, 33)

        return buffer
    }

    toDER(): Buffer {
        const rBa = this.r.toDERInteger()
        const sBa = this.s.toDERInteger()

        let sequence = []

        // INTEGER
        sequence.push(0x02, rBa.length)
        sequence = sequence.concat(rBa)

        // INTEGER
        sequence.push(0x02, sBa.length)
        sequence = sequence.concat(sBa)

        // SEQUENCE
        sequence.unshift(0x30, sequence.length)

        return new Buffer(sequence)
    }

    toScriptSignature(hashType: number) {
        const hashTypeBuffer = new Buffer(1)
        hashTypeBuffer.writeUInt8(hashType, 0)

        return Buffer.concat([this.toDER(), hashTypeBuffer])
    }
}
