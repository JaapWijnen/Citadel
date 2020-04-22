// Read more at: https://wiki.openssl.org/index.php/Diffie_Hellman

import NIO
import Crypto
import CCryptoBoringSSL

final class DHServerParameters {
    let identificationString: String
    let kexInitBuffer: ByteBuffer
//    let hostKeyType: ServerKeyExchangeMethod
    let serverPublicKey: UnsafeMutablePointer<BIGNUM>
//    let hostKey: HostKey
    let signature: ByteBuffer
    let hostKey: ByteBuffer
    let e: UnsafeMutablePointer<BIGNUM>
    let n: UnsafeMutablePointer<BIGNUM>
    
    // For testing purposes
    internal init(
        publicKey: UnsafeMutablePointer<BIGNUM>,
        rsa: (e: UnsafeMutablePointer<BIGNUM>, n: UnsafeMutablePointer<BIGNUM>),
        hostKey: ByteBuffer,
        signature: ByteBuffer,
        identificationString: String,
        kexInit: ByteBuffer
    ) {
        self.serverPublicKey = publicKey
        self.e = rsa.e
        self.n = rsa.n
        self.kexInitBuffer = kexInit
        self.identificationString = identificationString
        self.hostKey = hostKey
        self.signature = signature
    }
    
    init(parsing buffer: inout ByteBuffer, kexInitBuffer: ByteBuffer, identificationString: String) throws {
        self.kexInitBuffer = kexInitBuffer
        
        guard
            buffer.readInteger(as: UInt8.self) == SSHPacketType.kexdhreply.rawValue,
            let hostKey = buffer.readSSH2Buffer(),
            let publicKey = buffer.readSSH2Bytes(),
            let hashSignature = buffer.readSSH2Buffer(),
            identificationString.starts(with: "SSH-2.0-")
        else {
            throw SSHError.corruptedServerParameters
        }
        
        var rsaHostKey = hostKey
        
        guard rsaHostKey.readSSH2String() == "ssh-rsa" else {
            throw SSHError.notRSA
        }
        guard let e = rsaHostKey.readMPBignum(), let n = rsaHostKey.readMPBignum() else {
            throw SSHError.badServerPubkey
        }
        
        self.hostKey = hostKey
        self.identificationString = identificationString
        self.serverPublicKey = CCryptoBoringSSL_BN_bin2bn(publicKey, publicKey.count, nil)
        self.signature = hashSignature
        self.e = e
        self.n = n
    }

    deinit {
        CCryptoBoringSSL_BN_free(serverPublicKey)
// TODO:        CCryptoBoringSSL_BN_free(e)
//        CCryptoBoringSSL_BN_free(n)
    }
}

public final class DHClientParameters {
    let identificationString: String
    var kexInitPayload: ByteBuffer {
        keyExchangeConfig.payload
    }
    let keyExchangeConfig: KeyExchangeInitialization
    fileprivate let _context: UnsafeMutablePointer<DH>
    
    public var context: DH {
        _context.pointee
    }
    
    init(
        keyExchangeConfig: KeyExchangeInitialization,
        appName: String,
        keys: SSHKeyGenerator
    ) {
        self.keyExchangeConfig = keyExchangeConfig
        
        guard !appName.contains(" ") else {
            fatalError()
        }
        
        self._context = keys.makeDHContext()
        self.identificationString = "SSH-2.0-" + appName
    }
    
    deinit {
        CCryptoBoringSSL_DH_free(_context)
    }
}

extension Array where Element == UInt8 {
    init(bignum: UnsafeMutablePointer<BIGNUM>) {
        var buffer = ByteBufferAllocator().buffer(capacity: Int(CCryptoBoringSSL_BN_num_bytes(bignum)))
        buffer.writeBignum(bignum)
        self = buffer.readBytes(length: buffer.readableBytes)!
    }
}

public final class DHClientServerParameters {
    let client: DHClientParameters
    let server: DHServerParameters
    let config: KeyExchangeConfig
    let secret: UnsafeMutablePointer<BIGNUM>!
    private(set) var exchangeHash = [UInt8](repeating: 0, count: 20)
    private(set) var sessionId = [UInt8](repeating: 0, count: 20)
    
    init(
        client: DHClientParameters,
        server: DHServerParameters,
        config: KeyExchangeConfig
    ) throws {
        self.client = client
        self.server = server
        self.config = config
        
        let secret = CCryptoBoringSSL_BN_new()
        
        let ctx = CCryptoBoringSSL_BN_CTX_new()
        defer { CCryptoBoringSSL_BN_CTX_free(ctx) }
        
        guard CCryptoBoringSSL_BN_mod_exp(
            secret,
            server.serverPublicKey,
            client._context.pointee.priv_key,
            client._context.pointee.p,
            ctx
        ) == 1 else {
            CCryptoBoringSSL_BN_free(secret)
            throw SSHError.keyExchangeMismatch
        }
        
        self.secret = secret
        
        var exchangeHashInput = ByteBufferAllocator().buffer(capacity: 4_000)
        
        exchangeHashInput.writeSSH2String(client.identificationString)
        exchangeHashInput.writeSSH2String(server.identificationString)
        
        var clientKexInitBuffer = client.kexInitPayload
        assert(clientKexInitBuffer.readerIndex == 0)
        exchangeHashInput.writeSSH2Buffer(&clientKexInitBuffer)
        
        var serverKexInitBuffer = server.kexInitBuffer
        assert(serverKexInitBuffer.readerIndex == 0)
        exchangeHashInput.writeSSH2Buffer(&serverKexInitBuffer)
        
        var hostKey = server.hostKey
        assert(hostKey.readerIndex == 0)
        exchangeHashInput.writeSSH2Buffer(&hostKey)
        
        // TODO: DH group exchanges hash more data here
        // https://github.com/libssh2/libssh2/blob/master/src/kex.c#L477
        
        exchangeHashInput.writePublicKey(client)
        exchangeHashInput.writeMPBignum(server.serverPublicKey)
        exchangeHashInput.writeMPBignum(self.secret)
        
        exchangeHashInput.withUnsafeReadableBytes { input in
            _ = CCryptoBoringSSL_SHA1(
                input.bindMemory(to: UInt8.self).baseAddress,
                input.count,
                &exchangeHash
            )
        }
        
        // These start off the same
        sessionId = exchangeHash

        guard try config.serverKeyExchange.verifyExchangeHash(
            clientHash: exchangeHash,
            server: server
        ) else {
            throw SSHError.keyExchangeMismatch
        }
    }
    
    deinit {
        CCryptoBoringSSL_BN_free(secret)
    }
}

// TODO: Use this everywhere
final class _BIGNUM {
    let raw: UnsafeMutablePointer<BIGNUM>
    
    init(raw: UnsafeMutablePointer<BIGNUM>) {
        self.raw = raw
    }
    
    deinit {
        CCryptoBoringSSL_BN_free(raw)
    }
}

extension ByteBuffer {
    mutating func readSimpleMPBignum() -> UnsafeMutablePointer<BIGNUM>? {
        guard let bytes = readSSH2Bytes() else {
            return nil
        }
        
        return CCryptoBoringSSL_BN_bin2bn(bytes, bytes.count, nil)
    }
    
    mutating func readMPBignum() -> UnsafeMutablePointer<BIGNUM>? {
        guard var bytes = readSSH2Bytes() else {
            return nil
        }
        
        if bytes[0] & 0x80 != 0 {
            // If this check fails, the bignum is negative. This is illegal in SSH2
            return nil
        }

        // If the bignum sent is large enough that it occupies the highest bit
        if bytes[0] == 0x00 {
            // Remove the 0x00 padding (used to indicate it is actually a positive bignum)
            bytes.removeFirst()
        }
        
        return CCryptoBoringSSL_BN_bin2bn(bytes, bytes.count, nil)
    }
    
    mutating func readSSH2Bytes() -> [UInt8]? {
        guard let size = readInteger(as: UInt32.self) else {
            return nil
        }
        
        return readBytes(length: Int(size))
    }
    
    mutating func readSSH2String() -> String? {
        guard let size = readInteger(as: UInt32.self) else {
            return nil
        }
        
        return readString(length: Int(size))
    }
    
    mutating func readSSH2Buffer() -> ByteBuffer? {
        guard let size = readInteger(as: UInt32.self) else {
            return nil
        }
        
        return readSlice(length: Int(size))
    }
    
    mutating func writePublicKey(_ parameters: DHClientParameters) {
        writeMPBignum(parameters.context.pub_key)
    }
    
    mutating func writeSSH2Buffer(_ buffer: inout ByteBuffer) {
        writeInteger(UInt32(buffer.readableBytes))
        writeBuffer(&buffer)
    }
    
    mutating func writeSSH2Bytes(_ bytes: [UInt8]) {
        writeInteger(UInt32(bytes.count))
        writeBytes(bytes)
    }
    
    mutating func writeSSH2String(_ string: String) {
        writeInteger(UInt32(string.utf8.count))
        writeString(string)
    }
    
    mutating func writeSSH2BufferPointer(_ buffer: UnsafeMutableBufferPointer<UInt8>) {
        writeInteger(UInt32(buffer.count))
        writeBytes(buffer)
    }
    
    /// See: https://tools.ietf.org/html/rfc4251#section-4.1
    ///
    /// Represents multiple precision integers in two's complement format,
    /// stored as a string, 8 bits per byte, MSB first.  Negative numbers
    /// have the value 1 as the most significant bit of the first byte of
    /// the data partition.  If the most significant bit would be set for
    /// a positive number, the number MUST be preceded by a zero byte.
    /// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    /// included.  The value zero MUST be stored as a string with zero
    /// bytes of data.
    ///
    /// By convention, a number that is used in modular computations in
    /// Z_n SHOULD be represented in the range 0 <= x < n.
    mutating func writeMPBignum(_ bignum: UnsafePointer<BIGNUM>) {
        let mpIntSizeOffset = writerIndex
        moveWriterIndex(forwardBy: 4)
        let size = writeBignum(bignum)
        setInteger(UInt32(size), at: mpIntSizeOffset)
    }
    
    @discardableResult
    mutating func writeBignum(_ bignum: UnsafePointer<BIGNUM>) -> Int {
        var size = (CCryptoBoringSSL_BN_num_bits(bignum) + 7) / 8
        writeWithUnsafeMutableBytes(minimumWritableBytes: Int(size + 1)) { buffer in
            let buffer = buffer.bindMemory(to: UInt8.self)

            buffer.baseAddress!.pointee = 0
            
            CCryptoBoringSSL_BN_bn2bin(bignum, buffer.baseAddress! + 1)
            
            if buffer[1] & 0x80 != 0 {
                size += 1
            } else {
                memmove(buffer.baseAddress, buffer.baseAddress! + 1, Int(size))
            }
            
            return Int(size)
        }
        
        return Int(size)
    }
}
