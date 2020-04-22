// Read more at: https://wiki.openssl.org/index.php/Diffie_Hellman
import NIO
import Crypto

/// For now import both modules for simplicity
/// - TODO: Put these back inside the `#if`s, we definitely don't want to pull in BoringSSL when it isn't in use
import DiscretionalPrecision
import CCryptoBoringSSL

// MARK: - Abstractions around the different math backends

#if DH_MATH_DISCRETIONAL

typealias DHHugeInteger = ArbitraryInt

#elseif DH_MATH_BIGNUM


typealias DHHugeInteger = _BIGNUM

final class _BIGNUM {
    static let ctx: ThreadSpecificVariable<OpaquePointer>
    
    let raw: UnsafeMutablePointer<BIGNUM>
    
    init(raw: UnsafeMutablePointer<BIGNUM>) {
        self.raw = raw
    }
    
    deinit {
        CCryptoBoringSSL_BN_free(raw)
    }
}

#else

#error("Please activate either DH_MATH_DISCRETIONAL or DH_MATH_BIGNUM in Package.swift")

#endif

// MARK: - Misc types

/// - Note: OpenSSL uses the name "RSAPublicKey" for the traditional PKCS#1 RSA
///   public key format which is nothing but a couple integers. The name
///   "RSA_PUBKEY" refers to the (very slightly) more modern PKCS#10
///   `SubjectPublicKeyInfo` format which encodes an OID for RSA and
///   encapsulates the PKCS#1 structure in a bit string. The only meaningful
///   difference is that the PKCS#10 encoding (often erroneously referred to as
///   a PKCS#8 encoding) can slightly better validate that its contents make
///   some vague modicum of sense, and of course it's around 16 bytes longer
///   when encoded as DER. OpenSSL has also been known to - with the very same
///   pathetic inattention to simplicity, comprehensibility, and safety as the
///   entire ASN.1 concept form start to finish - refer to RSAPublicKey as being
///   version 0 and RSA_PUBKEY as being - well, possibly something else, which
///   is definitively wrong. RFC 3447 defines version 1 as "multi-prime" RSA,
///   which has nothing to do with the SPKI encoding.
//
///   In short, things get real confusing real fast, stick to the basics as much
///   as you can or you'll be left too dizzy to stand up, just like me!
struct RSAPublicKey { // "version 0" PKCS#1 pubkey - real old-school, almost mind-shredding in its sheer simplicity
    let modulus: DHHugeInteger        // n
    let publicExponent: DHHugeInteger // e
}


// MARK: - DH implementation

/// A set of parameters corresponding to data elements known about, gathered
/// from, and/or computed regarding a remote server. The parameters are expected
/// to be suitable to the purpose of performing a Diffie-Hellman key exchange
/// between the server thusly represented and a corresponding set of
/// `DHClientParameters` (see below).
final class DHServerParameters {
    
    /// Server version identifier in string form, e.g. "SSH-2.0-babeld-a950f115"
    let identificationString: String
    
    /// The complete payload of the server's `SSH_MSG_KEXINIT` packet.
    let kexInitBuffer: ByteBuffer
//    let hostKeyType: ServerKeyExchangeMethod
//    let hostKey: HostKey
    
    /// The server's exchange value, serving as its public key for the DH exchange. Also called `f`.
    let serverPublicKey: DHHugeInteger
    let signature: ByteBuffer
    let hostKey: ByteBuffer
    let rsa: RSAPublicKey
    
    // For testing purposes
    internal init(
        publicKey: DHHugeInteger,
        rsa: RSAPublicKey,
        hostKey: ByteBuffer,
        signature: ByteBuffer,
        identificationString: String,
        kexInit: ByteBuffer
    ) {
        self.serverPublicKey = publicKey
        self.rsa = rsa
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
        self.rsa = RSAPublicKey(modulus: n, publicExponent: e)
    }

    deinit {
        CCryptoBoringSSL_BN_free(serverPublicKey)
// TODO:        CCryptoBoringSSL_BN_free(e)
//        CCryptoBoringSSL_BN_free(n)
    }
}

public final class DHClientParameters {
    let identificationString: String // Client version identifier, e.g. "SSH-2.0-OpenSSH_8.1"
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
    init(bignum: DHHugeInteger) {
        var buffer = ByteBufferAllocator().buffer(capacity: Int(CCryptoBoringSSL_BN_num_bytes(bignum)))
        buffer.writeBignum(bignum)
        self = buffer.readBytes(length: buffer.readableBytes)!
    }
}

public final class DHClientServerParameters {
    let client: DHClientParameters
    let server: DHServerParameters
    let config: KeyExchangeConfig
    let secret: DHHugeInteger!
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

extension ByteBuffer {
    mutating func readSimpleMPBignum() -> DHHugeInteger? {
        guard let bytes = readSSH2Bytes() else {
            return nil
        }
        
        return CCryptoBoringSSL_BN_bin2bn(bytes, bytes.count, nil)
    }
    
    mutating func readMPBignum() -> DHHugeInteger? {
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
