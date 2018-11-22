import {instanta, instantateSha1, instantateSha256} from 'bitcoin-ts'
import createHash from 'create-hash'
import createHmac from 'create-hmac'
import {Buffer} from 'safe-buffer'
import {IData, IEncodingType} from './types'

export function sha1(data: IData, resultEncoding: IEncodingType) {
    return createHash('sha1').update(data).digest(resultEncoding)
}

export function sha256(data: IData, resultEncoding?: IEncodingType) {
    return createHash('sha256').update(data).digest(resultEncoding)
}

export function sha512(data: IData, resultEncoding?: IEncodingType) {
    return createHash('sha512').update(data).digest(resultEncoding)
}

export function ripemd160(data: IData) {
    return createHash('rmd160').update(data).digest()
}


export function HmacSHA256(buffer: Buffer, secret: Buffer) {
    return createHmac('sha256', secret).update(buffer).digest()
}
