// Wire-compatible with 0g-storage-client commit 6d39443.
// v1: [version=0x01][nonce:16]                     — 17 bytes
// v2: [version=0x02][ephemeralPub:33][nonce:16]    — 50 bytes

export const SYMMETRIC_VERSION = 1
export const ECIES_VERSION = 2
export const SYMMETRIC_HEADER_SIZE = 17
export const EPHEMERAL_PUBKEY_SIZE = 33
export const ECIES_HEADER_SIZE = 1 + EPHEMERAL_PUBKEY_SIZE + 16

export class EncryptionHeader {
    constructor(
        public version: number,
        public nonce: Uint8Array,
        public ephemeralPub: Uint8Array = new Uint8Array(EPHEMERAL_PUBKEY_SIZE)
    ) {
        if (nonce.length !== 16) {
            throw new Error(`nonce must be 16 bytes, got ${nonce.length}`)
        }
        if (ephemeralPub.length !== EPHEMERAL_PUBKEY_SIZE) {
            throw new Error(
                `ephemeralPub must be ${EPHEMERAL_PUBKEY_SIZE} bytes, got ${ephemeralPub.length}`
            )
        }
    }

    size(): number {
        return this.version === ECIES_VERSION
            ? ECIES_HEADER_SIZE
            : SYMMETRIC_HEADER_SIZE
    }

    toBytes(): Uint8Array {
        if (this.version === ECIES_VERSION) {
            const buf = new Uint8Array(ECIES_HEADER_SIZE)
            buf[0] = this.version
            buf.set(this.ephemeralPub, 1)
            buf.set(this.nonce, 1 + EPHEMERAL_PUBKEY_SIZE)
            return buf
        }
        const buf = new Uint8Array(SYMMETRIC_HEADER_SIZE)
        buf[0] = this.version
        buf.set(this.nonce, 1)
        return buf
    }
}

export function parseEncryptionHeader(data: Uint8Array): EncryptionHeader {
    if (data.length < 1) {
        throw new Error(`data too short for encryption header: ${data.length}`)
    }
    const version = data[0]
    switch (version) {
        case SYMMETRIC_VERSION: {
            if (data.length < SYMMETRIC_HEADER_SIZE) {
                throw new Error(
                    `data too short for v1 encryption header: ${data.length} < ${SYMMETRIC_HEADER_SIZE}`
                )
            }
            return new EncryptionHeader(version, data.slice(1, 17))
        }
        case ECIES_VERSION: {
            if (data.length < ECIES_HEADER_SIZE) {
                throw new Error(
                    `data too short for v2 encryption header: ${data.length} < ${ECIES_HEADER_SIZE}`
                )
            }
            return new EncryptionHeader(
                version,
                data.slice(
                    1 + EPHEMERAL_PUBKEY_SIZE,
                    1 + EPHEMERAL_PUBKEY_SIZE + 16
                ),
                data.slice(1, 1 + EPHEMERAL_PUBKEY_SIZE)
            )
        }
        default:
            throw new Error(`unsupported encryption version: ${version}`)
    }
}
