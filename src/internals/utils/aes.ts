import assert from 'assert'
import crypto from 'browserify-aes'
import ByteBuffer from 'bytebuffer'
import randomBytes from 'randombytes'
import {Buffer} from 'safe-buffer'
import {sha256, sha512} from '../hash'
import PrivateKey from '../PrivateKey'
import {PublicKey} from '../PublicKey'
import {IData} from '../types'

const Long = ByteBuffer.Long

/**
 https://steemit.com/steem/@dantheman/how-to-encrypt-a-memo-when-transferring-steem
 */

export function encrypt(private_key: PrivateKey, public_key: PublicKey, message: Buffer, nonce: string = uniqueNonce()): { nonce: string, message: Buffer, checksum: number } {
    return crypt(private_key, public_key, nonce, message)
}

export function decrypt(private_key: PrivateKey, public_key: PublicKey, nonce: string, message: Buffer, checksum: number) {
    return crypt(private_key, public_key, nonce, message, checksum).message
}

function crypt(private_key: PrivateKey, public_key: PublicKey, nonce: string, message: Buffer, checksum?: number) {
    private_key = PrivateKey(private_key)
    if (!private_key)
        throw new TypeError('private_key is required')

    public_key = new PublicKey(public_key)
    if (!public_key)
        throw new TypeError('public_key is required')

    nonce = toLongObj(nonce)
    if (!nonce)
        throw new TypeError('nonce is required')

    if (!Buffer.isBuffer(message)) {
        if (typeof message !== 'string')
            throw new TypeError('message should be buffer or string')
        message = new Buffer(message, 'binary')
    }
    if (checksum && typeof checksum !== 'number')
        throw new TypeError('checksum should be a number')

    const S = private_key.getSharedSecret(public_key)
    let ebuf = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN)
    ebuf.writeUint64(nonce)
    ebuf.append(S.toString('binary'), 'binary')
    ebuf = new Buffer(ebuf.copy(0, ebuf.offset).toBinary(), 'binary')
    const encryption_key = sha512(ebuf)

    // D E B U G
    // console.log('crypt', {
    //     priv_to_pub: private_key.toPublic().toString(),
    //     pub: public_key.toString(),
    //     nonce: nonce.toString(),
    //     message: message.length,
    //     checksum,
    //     S: S.toString('hex'),
    //     encryption_key: encryption_key.toString('hex'),
    // })

    const iv = encryption_key.slice(32, 48)
    const key = encryption_key.slice(0, 32)

    // check is first 64 bit of sha256 hash treated as uint64_t truncated to 32 bits.
    let check = sha256(encryption_key)
    check = check.slice(0, 4)
    const cbuf = ByteBuffer.fromBinary(check.toString('binary'), ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN)
    check = cbuf.readUint32()

    if (checksum) {
        if (check !== checksum)
            throw new Error('Invalid key')
        message = cryptoJsDecrypt(message, key, iv)
    } else {
        message = cryptoJsEncrypt(message, key, iv)
    }
    return {nonce, message, checksum: check}
}

function cryptoJsDecrypt(message: IData, key: IData, iv: IData): Buffer {
    assert(message, 'Missing cipher text')
    message = toBinaryBuffer(message)
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    // decipher.setAutoPadding(true)
    message = Buffer.concat([decipher.update(message), decipher.final()])
    return message
}

function cryptoJsEncrypt(message: IData, key: IData, iv: IData): Buffer {
    assert(message, 'Missing plain text')
    message = toBinaryBuffer(message)
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
    // cipher.setAutoPadding(true)
    message = Buffer.concat([cipher.update(message), cipher.final()])
    return message
}

/**
 * @return {string} unique 64 bit unsigned number string.
 * Being time based, this is careful to never choose the same nonce twice.
 * This value could be recorded in the blockchain for a long time.
 */
function uniqueNonce(): string {
    if (unique_nonce_entropy === null) {
        const b = new Uint8Array(randomBytes(2))
        unique_nonce_entropy = parseInt(b[0] << 8 | b[1], 10)
    }
    let long = Long.fromNumber(Date.now())
    const entropy = ++unique_nonce_entropy % 0xFFFF
    long = long.shiftLeft(16).or(Long.fromNumber(entropy))
    return long.toString()
}

let unique_nonce_entropy: null | number = null
// for(let i=1; i < 10; i++) key.uniqueNonce()

const toLongObj = (o: string) => (o ? Long.isLong(o) ? o : Long.fromString(o) : o)
const toBinaryBuffer = (o: string) => (o ? Buffer.isBuffer(o) ? o : new Buffer(o, 'binary') : o)
