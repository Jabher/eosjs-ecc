import {Buffer} from 'safe-buffer'

export default function enforce(type: string, value: any) { // Copied from https://github.com/bitcoinjs/bitcoinjs-lib
    switch (type) {
        case 'Array':
            if (Array.isArray(value)) return
            break
        case 'Boolean':
            if (typeof value === 'boolean') return
            break
        case 'Buffer':
            if (Buffer.isBuffer(value)) return
            break
        case 'Number':
            if (typeof value === 'number') return
            break
        case 'String':
            if (typeof value === 'string') return
            break
        default:
            if (getName(value.constructor) === type) return
    }

    throw new TypeError(`Expected ${getName(type) || type}, got ${value}`)
};

function getName(fn: Function | string) {
    // Why not fn.name: https://kangax.github.io/compat-table/es6/#function_name_property
    const match = fn.toString().match(/function (.*?)\(/)
    return match ? match[1] : null
}
