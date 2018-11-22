import {PrivateKey} from './internals/PrivateKey'
import {PublicKey} from './internals/PublicKey'
import {Signature} from './internals/signature'
import {IData, IEncodingType} from './internals/types'

export {sha256} from './internals/hash'

/**
 [Wallet Import Format](https://en.bitcoin.it/wiki/Wallet_import_format)
 @typedef {string} wif
 */
/**
 EOSKey..
 @typedef {string} pubkey
 */

/** @namespace */
/**
 Initialize by running some self-checking code.  This should take a
 second to gather additional CPU entropy used during private key
 generation.

 Initialization happens once even if called multiple times.
 */
export const initialize = PrivateKey.initialize

/** Does not pause to gather CPU entropy */

export const unsafeRandomKey = async (): Promise<string> => {
    const key = await PrivateKey.unsafeRandomKey()
    return key.toString()
}

/**
 @arg {number} [cpuEntropyBits = 0] gather additional entropy
 from a CPU mining algorithm.  This will already happen once by
 default.
 */
export const randomKey = async (cpuEntropyBits: number = 0): Promise<string> => {
    const key = await PrivateKey.randomKey(cpuEntropyBits)
    return key.toString()
}

/**

 @arg {string} seed - any length string.  This is private.  The same
 seed produces the same private key every time.  At least 128 random
 bits should be used to produce a good private key.
 */
export const seedPrivate = (seed: string): string => PrivateKey.fromSeed(seed).toString()

export const privateToPublic = (wif: string, pubkey_prefix = 'EOS'): string =>
    PrivateKey.fromString(wif).toPublic().toString(pubkey_prefix)

export const isValidPublic = (pubkey: IData | PublicKey, pubkey_prefix = 'EOS') =>
    PublicKey.isValid(pubkey, pubkey_prefix)

export const isValidPrivate = (wif: string): boolean => PrivateKey.isValid(wif)

export const sign = (data: IData, privateKey: IData | PrivateKey, encoding: boolean | string = 'utf8'): string => {
    if (encoding === true) {
        throw new TypeError('API changed, use signHash(..) instead')
    } else if (encoding === false) {
        console.log('Warning: ecc.sign hashData parameter was removed')
        return Signature.sign(data, privateKey).toString()
    } else {
        return Signature.sign(data, privateKey, encoding).toString()
    }
}

export const signHash = (dataSha256: IData, privateKey: IData | PrivateKey, encoding: string = 'hex'): string =>
    Signature.signHash(dataSha256, privateKey, encoding).toString()

export const verify = (signature: IData, data: IData, pubkey: IData | PublicKey, encoding: boolean | IEncodingType = 'utf8') => {
    if (encoding === true) {
        throw new TypeError('API changed, use verifyHash(..) instead')
    } else if (encoding === false) {
        console.log('Warning: ecc.verify hashData parameter was removed')
        return Signature.from(signature).verify(data, pubkey)
    } else {
        return Signature.from(signature).verify(data, pubkey, encoding)
    }
}

export const verifyHash = (signature: IData, dataSha256: IData, pubkey: IData | PublicKey, encoding = 'hex') =>
    Signature.from(signature).verifyHash(dataSha256, pubkey, encoding)

export const recover = (signature: IData, data: IData, encoding: boolean | IEncodingType = 'utf8'): string => {
    if (encoding === true) {
        throw new TypeError('API changed, use recoverHash(signature, data) instead')
    } else if (encoding === false) {
        console.log('Warning: ecc.recover hashData parameter was removed')
        return Signature.from(signature).recover(data).toString()
    } else {
        return Signature.from(signature).recover(data, encoding).toString()
    }
}

export const recoverHash = (signature: IData, dataSha256: IData, encoding: IEncodingType = 'hex'): string =>
    Signature.from(signature).recoverHash(dataSha256, encoding).toString()
