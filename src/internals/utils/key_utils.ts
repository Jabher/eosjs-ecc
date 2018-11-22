import assert from 'assert'
import base58 from 'bs58'
import randomBytes from 'randombytes'
import {Buffer} from 'safe-buffer'
import {ripemd160, sha256} from '../hash'
import {IData} from '../types'

let entropyPos = 0
export let entropyCount = 0

const externalEntropyArray = randomBytes(101)

/**
 Additional forms of entropy are used.  A week random number generator can run out of entropy.  This should ensure even the worst random number implementation will be reasonably safe.

 @arg {number} [cpuEntropyBits = 0] generate entropy on the fly.  This is
 not required, entropy can be added in advanced via addEntropy or initialize().

 @arg {boolean} [safe = true] false for testing, otherwise this will be
 true to ensure initialize() was called.

 @return a random buffer obtained from the secure random number generator.  Additional entropy is used.
 */
export function random32ByteBuffer({cpuEntropyBits = 0, safe = true} = {}) {
    assert.equal(typeof cpuEntropyBits, 'number', 'cpuEntropyBits')
    assert.equal(typeof safe, 'boolean', 'boolean')

    if (safe) {
        assert(entropyCount >= 128, 'Call initialize() to add entropy')
    }

    // if(entropyCount > 0) {
    //     console.log(`Additional private key entropy: ${entropyCount} events`)
    // }

    const hash_array = []
    hash_array.push(randomBytes(32))
    hash_array.push(Buffer.from(cpuEntropy(cpuEntropyBits)))
    hash_array.push(externalEntropyArray)
    hash_array.push(browserEntropy())
    return sha256(Buffer.concat(hash_array))
}

/**
 Adds entropy.  This may be called many times while the amount of data saved
 is accumulatively reduced to 101 integers.  Data is retained in RAM for the
 life of this module.

 @example React <code>
 componentDidMount() {
        this.refs.MyComponent.addEventListener("mousemove", this.onEntropyEvent, {capture: false, passive: true})
    }
 componentWillUnmount() {
        this.refs.MyComponent.removeEventListener("mousemove", this.onEntropyEvent);
    }
 onEntropyEvent = (e) => {
        if(e.type === 'mousemove')
            key_utils.addEntropy(e.pageX, e.pageY, e.screenX, e.screenY)
        else
            console.log('onEntropyEvent Unknown', e.type, e)
    }
 </code>
 */
export function addEntropy(...ints: number[]) {
    assert.equal(externalEntropyArray.length, 101, 'externalEntropyArray')

    entropyCount += ints.length
    for (const i of ints) {
        const pos = entropyPos++ % 101
        const i2 = externalEntropyArray[pos] += i
        if (i2 > 9007199254740991)
            externalEntropyArray[pos] = 0
    }
}

/**
 This runs in just under 1 second and ensures a minimum of cpuEntropyBits
 bits of entropy are gathered.

 Based on more-entropy. @see https://github.com/keybase/more-entropy/blob/master/src/generator.iced

 @arg {number} [cpuEntropyBits = 128]
 @return {array} counts gathered by measuring variations in the CPU speed during floating point operations.
 */
export function cpuEntropy(cpuEntropyBits = 128) {
    let collected = []
    let lastCount = null
    let lowEntropySamples = 0
    while (collected.length < cpuEntropyBits) {
        const count = floatingPointCount()
        if (lastCount != null) {
            const delta = count - lastCount
            if (Math.abs(delta) < 1) {
                lowEntropySamples++
                continue
            }
            // how many bits of entropy were in this sample
            const bits = Math.floor(log2(Math.abs(delta)) + 1)
            if (bits < 4) {
                if (bits < 2) {
                    lowEntropySamples++
                }
                continue
            }
            collected.push(delta)
        }
        lastCount = count
    }
    if (lowEntropySamples > 10) {
        const pct = Number(lowEntropySamples / cpuEntropyBits * 100).toFixed(2)
        // Is this algorithm getting inefficient?
        console.warn(`WARN: ${pct}% low CPU entropy re-sampled`)
    }
    return collected
}

/**
 @private
 Count while performing floating point operations during a fixed time
 (7 ms for example).  Using a fixed time makes this algorithm
 predictable in runtime.
 */
export function floatingPointCount() {
    const workMinMs = 7
    const d = Date.now()
    let i = 0
    let x = 0
    while (Date.now() < d + workMinMs + 1) {
        x = Math.sin(Math.sqrt(Math.log(++i + x)))
    }
    return i
}

export const log2 = (x: number) => Math.log(x) / Math.LN2

/**
 @private
 Attempt to gather and hash information from the browser's window, history, and supported mime types.  For non-browser environments this simply includes secure random data.  In any event, the information is re-hashed in a loop for 25 milliseconds seconds.
 */
export function browserEntropy(): Buffer {
    let entropyStr = Array(randomBytes(101)).join()
    try {
        entropyStr += `${(new Date()).toString()} ${window.screen.height} ${window.screen.width} ${window.screen.colorDepth}  ${window.screen.availHeight} ${window.screen.availWidth} ${window.screen.pixelDepth}${navigator.language} ${window.location} ${window.history.length}`

        for (let i = 0, mimeType; i < navigator.mimeTypes.length; i++) {
            mimeType = navigator.mimeTypes[i]
            entropyStr += `${mimeType.description} ${mimeType.type} ${mimeType.suffixes} `
        }
    } catch (error) {
        //nodejs:ReferenceError: window is not defined
        entropyStr += sha256((new Date()).toString())
    }

    const b = new Buffer(entropyStr)
    entropyStr += `${b.toString('binary')} ${(new Date()).toString()}`

    let entropy: Buffer = new Buffer(entropyStr)
    const start_t = Date.now()
    while (Date.now() - start_t < 25)
        entropy = sha256(entropy)

    return entropy
}

export function checkEncode(keyBuffer: Buffer, keyType: null | string = null) {
    assert(Buffer.isBuffer(keyBuffer), 'expecting keyBuffer<Buffer>')
    if (keyType === 'sha256x2') { // legacy
        const checksum = sha256(sha256(keyBuffer)).slice(0, 4)
        return base58.encode(Buffer.concat([keyBuffer, checksum]))
    } else {
        const check = [keyBuffer]
        if (keyType) {
            check.push(Buffer.from(keyType))
        }
        const checksum = ripemd160(Buffer.concat(check)).slice(0, 4)
        return base58.encode(Buffer.concat([keyBuffer, checksum]))
    }
}

export function checkDecode(keyString: IData, keyType: string | null = null): Buffer {
    assert(keyString != null, 'private key expected')
    const buffer = new Buffer(base58.decode(keyString))
    const checksum = buffer.slice(-4)
    const key = buffer.slice(0, -4)

    let newCheck
    if (keyType === 'sha256x2') { // legacy
        newCheck = sha256(sha256(key)).slice(0, 4) // WIF (legacy)
    } else {
        const check = [key]
        if (keyType) {
            check.push(Buffer.from(keyType))
        }
        newCheck = ripemd160(Buffer.concat(check)).slice(0, 4) //PVT
    }

    if (checksum.toString() !== newCheck.toString()) {
        throw new Error(`Invalid checksum, ${`${checksum.toString('hex')} != ${newCheck.toString('hex')}`}`
        )
    }

    return key
}
