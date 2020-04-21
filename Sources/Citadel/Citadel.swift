/// An implementation of: https://tools.ietf.org/html/rfc4253#page-21

import Foundation
import NIO
import Crypto
import CCryptoBoringSSL

enum SSHClientMessage {
    case versionExchange(String)
    case kexInit(KeyExchangeInitialization)
    case kexDhInit(DHClientParameters)
    case dhAcceptKeys
    case requestService(String)
    case authenticatePassword(username: String, password: String)
}

enum SSHServerMessage {
    case banner(String)
    case other(SSHPacket)
}

fileprivate extension Optional {
    func assert() throws -> Wrapped {
        guard let me = self else {
            throw SSHError.keyExchangeMismatch
        }
        
        return me
    }
}

struct KeyExchangeConfig {
    let kexAlgorithm: KeyExchangeAlgorithm
    let serverKeyExchange: ServerKeyExchangeMethod
    let clientEncryption: EncryptionMethod
    let serverEncryption: EncryptionMethod
    let clientMac: MessageAuthenticationAlgorithm
    let serverMac: MessageAuthenticationAlgorithm
    let clientCompression: CompressionAlgorithm
    let serverCompression: CompressionAlgorithm
    let clientLanguage: String?
    let serverLanguage: String?
    
    init(client: KeyExchangeInitialization, server: KeyExchangeInitialization) throws {
        kexAlgorithm = try pick(keyPath: \.kexAlgorithms, client: client, server: server).assert()
        serverKeyExchange = try pick(keyPath: \.serverKeyAlgorithms, client: client, server: server).assert()
        clientEncryption = try pick(keyPath: \.clientEncryptionAlgorithms, client: client, server: server).assert()
        serverEncryption = try pick(keyPath: \.serverEncryptionAlgorithms, client: client, server: server).assert()
        clientMac = try pick(keyPath: \.clientMacAlgorithms, client: client, server: server).assert()
        serverMac = try pick(keyPath: \.serverMacAlgorithms, client: client, server: server).assert()
        clientCompression = try pick(keyPath: \.clientCompressionAlgorithms, client: client, server: server).assert()
        serverCompression = try pick(keyPath: \.serverCompressionAlgorithms, client: client, server: server).assert()
        clientLanguage = pick(keyPath: \.clientLanguages, client: client, server: server)
        serverLanguage = pick(keyPath: \.serverLanguages, client: client, server: server)
    }
}

private func pick<T: Equatable>(keyPath: KeyPath<KeyExchangeInitialization, [T]>, client: KeyExchangeInitialization, server: KeyExchangeInitialization) -> T? {
    for element in client[keyPath: keyPath] {
        if server[keyPath: keyPath].contains(element) {
            return element
        }
    }
    
    return nil
}

/// All supported algorithms in order of preference
/// Chosen by selecting the first algorithm on the client's preferences that the server also supports
final class KeyExchangeInitialization {
    var cookie: ByteBuffer
    
    var kexAlgorithms: [KeyExchangeAlgorithm] = [ .dhGroup14Sha1 ]
    var serverKeyAlgorithms: [ServerKeyExchangeMethod] = [ .sshRsa ]
    
    var clientEncryptionAlgorithms: [EncryptionMethod] = [ .aes128ctr ]
    var serverEncryptionAlgorithms: [EncryptionMethod] = [ .aes128ctr ]
    
    var clientMacAlgorithms: [MessageAuthenticationAlgorithm] = [ .hmacSHA256 ]
    var serverMacAlgorithms: [MessageAuthenticationAlgorithm] = [ .hmacSHA256 ]
    
    var clientCompressionAlgorithms: [CompressionAlgorithm] = [ .none ]
    var serverCompressionAlgorithms: [CompressionAlgorithm] = [ .none ]
    
    var clientLanguages = [String]()
    var serverLanguages = [String]()
    
    var firstKexPacketFollows = false
    private(set) var payload: ByteBuffer!
    
    init(allocator: ByteBufferAllocator) {
        // Cookie, 16 random bytes
        var cookie = allocator.buffer(capacity: 16)
        var rng = SystemRandomNumberGenerator()
        cookie.writeInteger(rng.next())
        cookie.writeInteger(rng.next())
        self.cookie = cookie
        var payload = allocator.buffer(capacity: 1000)
        self.write(into: &payload)
        self.payload = payload
    }
    
    init?(parsing buffer: inout ByteBuffer) throws {
        self.payload = buffer
        
        guard
            buffer.readInteger(as: UInt8.self) == SSHPacketType.kexinit.rawValue,
            let cookie = buffer.readSlice(length: 16),
            let kex = buffer.readNameList(),
            let serverKeyAlgorithms = buffer.readNameList(),
            let clientEncryption = buffer.readNameList(),
            let serverEncryption = buffer.readNameList(),
            let clientMac = buffer.readNameList(),
            let serverMac = buffer.readNameList(),
            let clientCompression = buffer.readNameList(),
            let serverCompression = buffer.readNameList(),
            let clientLanguages = buffer.readNameList(),
            let serverLanguages = buffer.readNameList(),
            let firstKexPacketFollows: UInt8 = buffer.readInteger(),
            buffer.readInteger(as: UInt32.self) != nil // Reserved bits
        else {
            return nil
        }
        
        guard firstKexPacketFollows == 0x00 || firstKexPacketFollows == 0x01 else {
            throw SSHError.protocolError
        }
        
        self.cookie = cookie
        
        self.kexAlgorithms = kex.compactMapString(KeyExchangeAlgorithm.init)
        self.serverKeyAlgorithms = serverKeyAlgorithms.compactMapString(ServerKeyExchangeMethod.init)
        
        self.clientEncryptionAlgorithms = clientEncryption.compactMapString(EncryptionMethod.init)
        self.serverEncryptionAlgorithms = serverEncryption.compactMapString(EncryptionMethod.init)
        
        self.clientMacAlgorithms = clientMac.compactMapString(MessageAuthenticationAlgorithm.init)
        self.serverMacAlgorithms = serverMac.compactMapString(MessageAuthenticationAlgorithm.init)
        
        self.clientCompressionAlgorithms = clientCompression.compactMapString(CompressionAlgorithm.init)
        self.serverCompressionAlgorithms = serverCompression.compactMapString(CompressionAlgorithm.init)
        
        self.clientLanguages = clientLanguages.map(String.init)
        self.serverLanguages = serverLanguages.map(String.init)
        
        self.firstKexPacketFollows = firstKexPacketFollows == 0x01
    }
    
    private func write(into buffer: inout ByteBuffer) {
        buffer.writeInteger(SSHPacketType.kexinit.rawValue)
        var cookie = self.cookie
        buffer.writeBuffer(&cookie)
        
        buffer.writeNameList(kexAlgorithms.map(\.rawValue))
        buffer.writeNameList(serverKeyAlgorithms.map(\.rawValue))
        
        buffer.writeNameList(clientEncryptionAlgorithms.map(\.rawValue))
        buffer.writeNameList(serverEncryptionAlgorithms.map(\.rawValue))
        
        buffer.writeNameList(clientMacAlgorithms.map(\.rawValue))
        buffer.writeNameList(serverMacAlgorithms.map(\.rawValue))
        
        buffer.writeNameList(clientCompressionAlgorithms.map(\.rawValue))
        buffer.writeNameList(serverCompressionAlgorithms.map(\.rawValue))
        
        buffer.writeNameList(clientLanguages)
        buffer.writeNameList(serverLanguages)
        
        buffer.writeInteger(firstKexPacketFollows ? 0x01 : 0x00, as: UInt8.self)
        buffer.writeInteger(0 as UInt32) // Reserved
    }
}

enum SSHLoginReply {
    case success, failure
    
    init?(parsing buffer: inout ByteBuffer) {
        switch buffer.readInteger(as: UInt8.self) {
        case SSHPacketType.userAuthSuccess.rawValue:
            self = .success
        case SSHPacketType.userAuthFailure.rawValue:
            self = .failure
        default:
            return nil
        }
    }
}

final class SSHStateContext {
    enum _State {
        enum BinaryPacketState {
            case keyExchange(EventLoopPromise<KeyExchangeInitialization>)
            case dhFirstKexPacket(KeyExchangeInitialization, EventLoopPromise<KeyExchangeInitialization>)
            case dhKeyExchange(String, kexInitBuffer: ByteBuffer, EventLoopPromise<DHServerParameters>)
            case awaitingKeyAcceptance(DHServerParameters, EventLoopPromise<DHServerParameters>)
            case encrypted
        }
        
        case versionExchange(EventLoopPromise<String>)
        case binaryPackets(BinaryPacketState)
    }
    
    struct Decryption {
        let serverCipher: EncryptionMethod
        let serverMac: MessageAuthenticationAlgorithm
        let params: DHClientServerParameters
        
        let encryptionKey: [UInt8]
        let integrityKey: [UInt8]
        let iv: [UInt8]
        
        init(
            serverCipher: EncryptionMethod,
            serverMac: MessageAuthenticationAlgorithm,
            params: DHClientServerParameters
        ) {
            self.serverCipher = serverCipher
            self.serverMac = serverMac
            self.params = params
            
            func calculateSha1Key(letter: UInt8, size: Int) -> [UInt8] {
                var result = [UInt8]()
                var hashOut = [UInt8](repeating: 0, count: 20)
                var hashInput = ByteBufferAllocator().buffer(capacity: 4_000)
                
                while result.count < size {
                    hashInput.moveWriterIndex(to: 0)
                    hashInput.writeMPBignum(params.secret)
                    hashInput.writeBytes(params.exchangeHash)
                    
                    if !result.isEmpty {
                        hashInput.writeBytes(result)
                    } else {
                        hashInput.writeInteger(letter)
                        hashInput.writeBytes(params.sessionId)
                    }
                    
                    hashInput.withUnsafeReadableBytes { input in
                        _ = CCryptoBoringSSL_SHA1(
                            input.bindMemory(to: UInt8.self).baseAddress,
                            input.count,
                            &hashOut
                        )
                    }
                    result += hashOut
                }
                
                result.removeLast(result.count - size)
                return result
            }
            
            self.iv = calculateSha1Key(letter: 66, size: serverCipher.ivSize) // 'B'
            self.encryptionKey = calculateSha1Key(letter: 68, size: serverCipher.keySize) // 'D'
            self.integrityKey = calculateSha1Key(letter: 70, size: serverMac.hashSize) // 'F'
        }
    }
    
    struct Encryption {
        // TODO: Copy first exchangeHash into session_id, when we support algorithm renegotiation
        // The first exchangeHash doubles as session_id
        let clientCipher: EncryptionMethod
        let clientMac: MessageAuthenticationAlgorithm
        let params: DHClientServerParameters
        
        let encryptionKey: [UInt8]
        let integrityKey: [UInt8]
        let iv: [UInt8]
        
        init(
            clientCipher: EncryptionMethod,
            clientMac: MessageAuthenticationAlgorithm,
            params: DHClientServerParameters
        ) {
            self.clientCipher = clientCipher
            self.clientMac = clientMac
            self.params = params
            
            func calculateSha1Key(letter: UInt8, size: Int) -> [UInt8] {
                var result = [UInt8]()
                var hashOut = [UInt8](repeating: 0, count: 20)
                var hashInput = ByteBufferAllocator().buffer(capacity: 4_000)
                
                while result.count < size {
                    hashInput.moveWriterIndex(to: 0)
                    hashInput.writeMPBignum(params.secret)
                    hashInput.writeBytes(params.exchangeHash)
                    
                    if !result.isEmpty {
                        hashInput.writeBytes(result)
                    } else {
                        hashInput.writeInteger(letter)
                        hashInput.writeBytes(params.sessionId)
                    }
                    
                    hashInput.withUnsafeReadableBytes { input in
                        _ = CCryptoBoringSSL_SHA1(
                            input.bindMemory(to: UInt8.self).baseAddress,
                            input.count,
                            &hashOut
                        )
                    }
                    result += hashOut
                }
                
                result.removeLast(result.count - size)
                return result
            }
            
            self.iv = calculateSha1Key(letter: 65, size: clientCipher.ivSize) // 'A'
            self.encryptionKey = calculateSha1Key(letter: 67, size: clientCipher.keySize) // 'C'
            self.integrityKey = calculateSha1Key(letter: 69, size: clientMac.hashSize) // 'E'
        }
    }
    
    let clientParameters: DHClientParameters
    var handlers = [UInt8: (SSHPacket) -> ()]()
    var fallbackHandler: (SSHPacket) -> () = { packet in
        print("unhandled packet \(packet)")
    }
    var serverIdentification: String?
    var state: _State
    private(set) var clientBlockSize: Int = 8
    private(set) var serverMacSize = 0
    
    private var decryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>?
    private var encryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>?
    private var messageDigest: ((UnsafeRawBufferPointer, UInt32) -> [UInt8])?
    public private(set) var verifyDigest: ((UnsafeRawBufferPointer, UInt32, [UInt8]) -> Bool)?
    
    init(
        promise: EventLoopPromise<String>,
        allocator: ByteBufferAllocator,
        keys: SSHKeyGenerator
    ) {
        state = .versionExchange(promise)
        let kexInit = KeyExchangeInitialization(allocator: allocator)
        
        clientParameters = DHClientParameters(
            keyExchangeConfig: kexInit,
            appName: "Citadel_1.0",
            keys: keys
        )
    }
    
    deinit {
        if let encryptionContext = encryptionContext {
            CCryptoBoringSSL_EVP_CIPHER_CTX_free(encryptionContext)
        }
    }
    
    func encryptAndMAC(_ buffer: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let digest = buffer.withUnsafeReadableBytes { buffer in
            self.messageDigest?(buffer, sequenceNumber)
        }
        
        try self.encrypt(&buffer)
        
        if let digest = digest {
            buffer.writeBytes(digest)
        }
    }
    
    func decrypt(_ buffer: UnsafeMutableRawBufferPointer) throws {
        guard let decryptionContext = decryptionContext else {
            return
        }
        
        guard buffer.count % Int(AES_BLOCK_SIZE) == 0 else {
            throw SSHError.protocolError
        }
        
        guard buffer.count < 40_000 else { // SSH wants us to limit to around 35 KB
            throw SSHError.packetSize
        }
        
        let out = UnsafeMutablePointer<UInt8>.allocate(capacity: buffer.count)
        defer { out.deallocate() }
        
        let buffer = buffer.bindMemory(to: UInt8.self)
        var i: Int32 = 0
        
        while i < buffer.count {
            guard CCryptoBoringSSL_EVP_Cipher(
                decryptionContext,
                out + Int(i),
                buffer.baseAddress?.advanced(by: Int(i)),
                Int(AES_BLOCK_SIZE)
            ) == 1 else {
                fatalError()
            }
            
            i += AES_BLOCK_SIZE
        }
        
        memcpy(buffer.baseAddress, out, buffer.count)
    }
    
    func initDecryption(_ decryption: Decryption) {
        self.verifyDigest = { buffer, sequenceNumber, mac in
            decryption.serverMac.hash(
                buffer: buffer,
                sequenceNumber: sequenceNumber,
                integrityKey: decryption.integrityKey
            ) == mac
        }
        
        let cipher: UnsafePointer<EVP_CIPHER>!
        
        switch decryption.serverCipher {
        case .aes256ctr:
            cipher = CCryptoBoringSSL_EVP_aes_256_ctr()
        case .aes192ctr:
            cipher = CCryptoBoringSSL_EVP_aes_192_ctr()
        case .aes128ctr:
            cipher = CCryptoBoringSSL_EVP_aes_128_ctr()
        }
        
        let decryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            cipher,
            decryption.encryptionKey,
            decryption.iv,
            1
        ) == 1 else {
            fatalError()
        }
        
        self.serverMacSize = decryption.serverMac.hashSize
        self.decryptionContext = decryptionContext
    }
    
    func initEncryption(_ encryption: Encryption) {
        self.messageDigest = { buffer, sequenceNumber in
            encryption.clientMac.hash(
                buffer: buffer,
                sequenceNumber: sequenceNumber,
                integrityKey: encryption.integrityKey
            )
        }
        
        let cipher: UnsafePointer<EVP_CIPHER>!
        
        switch encryption.clientCipher {
        case .aes256ctr:
            cipher = CCryptoBoringSSL_EVP_aes_256_ctr()
        case .aes192ctr:
            cipher = CCryptoBoringSSL_EVP_aes_192_ctr()
        case .aes128ctr:
            cipher = CCryptoBoringSSL_EVP_aes_128_ctr()
        }
        
        let encryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            cipher,
            encryption.encryptionKey,
            encryption.iv,
            1
        ) == 1 else {
            fatalError()
        }
        
        self.clientBlockSize = encryption.clientCipher.blockSize
        self.encryptionContext = encryptionContext
    }
    
    func encrypt(_ buffer: inout ByteBuffer) throws {
        guard let encryptionContext = encryptionContext else {
            return
        }
        
        guard buffer.readableBytes < 40_000 else { // SSH wants us to limit to around 35 KB
            throw SSHError.packetSize
        }
        
        assert(buffer.writerIndex % Int(AES_BLOCK_SIZE) == 0)
        
        let out = UnsafeMutablePointer<UInt8>.allocate(capacity: buffer.writerIndex)
        defer { out.deallocate() }
        
        buffer.withUnsafeReadableBytes { buffer in
            let buffer = buffer.bindMemory(to: UInt8.self)
            var i: Int32 = 0
            
            while i < buffer.count {
                guard CCryptoBoringSSL_EVP_Cipher(
                    encryptionContext,
                    out + Int(i),
                    buffer.baseAddress?.advanced(by: Int(i)),
                    Int(AES_BLOCK_SIZE)
                ) == 1 else {
                    fatalError()
                }
                
                i += AES_BLOCK_SIZE
            }
        }
        
        let outBuffer = UnsafeMutableBufferPointer(
            start: out,
            count: buffer.writerIndex
        )
        buffer.setBytes(outBuffer, at: 0)
    }
}

final class SSHPacketEncoder: MessageToByteEncoder {
    typealias OutboundIn = SSHClientMessage
    
    let context: SSHStateContext
    var sequence: UInt32 = 0
    
    init(context: SSHStateContext) {
        self.context = context
    }
    
    func encode(data: SSHClientMessage, out: inout ByteBuffer) throws {
        if case .versionExchange(let version) = data {
            out.writeString(version)
            out.writeString("\r\n")
            return
        }
        
        defer { sequence = sequence &+ 1 }
        
        let packetLengthIndex = out.writerIndex
        out.moveWriterIndex(forwardBy: 4)
        
        let paddingLengthIndex = out.writerIndex
        out.moveWriterIndex(forwardBy: 1)
        var payloadSize = out.writerIndex
        
        switch data {
        case .versionExchange:
            fatalError("Cannot reach here, what did the programmer do now?!")
        case .kexInit(let kexInit):
            var payload = kexInit.payload!
            out.writeBuffer(&payload)
        case .kexDhInit(let parameters):
            out.writeInteger(SSHPacketType.kexdhinit.rawValue)
            out.writePublicKey(parameters)
        case .dhAcceptKeys:
            out.writeInteger(SSHPacketType.newkeys.rawValue)
        case .requestService(let service):
            out.writeInteger(SSHPacketType.serviceRequest.rawValue)
            out.writeInteger(UInt32(service.utf8.count))
            out.writeString(service)
        case .authenticatePassword(let username, let password):
            out.writeInteger(SSHPacketType.userAuthRequest.rawValue)
            
            out.writeSSH2String(username)
            out.writeSSH2String("ssh-connection")
            out.writeSSH2String("password")
            
            // If true, this indicates that it's probing for support
            // However, this is false so we're doing it for realsies now!
            out.writeInteger(0x00 as UInt8)
            
            
            out.writeSSH2String(password)
        }
        
        payloadSize = out.writerIndex - payloadSize
        // new size - old size = added bytes
        
        let blockSize = self.context.clientBlockSize
        var paddingLength = blockSize - (out.writerIndex % blockSize)
        if paddingLength < 4 {
            paddingLength += blockSize
        }
        
        // 5 = UInt32 + UInt8 lengths
        if 5 + payloadSize + paddingLength < 16 {
            paddingLength = 16 - 5 - payloadSize
        }
        
        out.setInteger(UInt32(1 + payloadSize + paddingLength), at: packetLengthIndex)
        out.setInteger(UInt8(paddingLength), at: paddingLengthIndex)
        
        out.writeWithUnsafeMutableBytes(minimumWritableBytes: paddingLength) { out in
            CCryptoBoringSSL_RAND_bytes(
                out.bindMemory(to: UInt8.self).baseAddress,
                paddingLength
            )
            
            return paddingLength
        }
        
        try context.encryptAndMAC(&out, sequenceNumber: sequence)
    }
}

final class SSHPacketDecoder: ByteToMessageDecoder {
    typealias InboundOut = SSHServerMessage
    
    let context: SSHStateContext
    var sequenceNumber: UInt32 = 0
     
    init(context: SSHStateContext) {
        self.context = context
    }
    
    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        switch self.context.state {
        case .versionExchange(let promise):
            guard let string = buffer.readStringUntilCRLN() else {
                return .needMoreData
            }
            
            guard string.starts(with: "SSH-2.0-") else {
                promise.fail(SSHError.protocolError)
                throw SSHError.protocolError
            }
            
            promise.succeed(string)
            return .continue
        case .binaryPackets(let substate):
            guard var packet = try buffer.readSSHPacket(context: self.context, sequenceNumber: sequenceNumber) else {
                return .needMoreData
            }
            
            sequenceNumber = sequenceNumber &+ 1
            
            switch substate {
            case .keyExchange(let promise):
                guard let kexInit = try KeyExchangeInitialization(parsing: &packet.payload) else {
                    promise.fail(SSHError.protocolError)
                    throw SSHError.protocolError
                }
                
                if kexInit.firstKexPacketFollows {
                    self.context.state = .binaryPackets(.dhFirstKexPacket(kexInit, promise))
                } else {
                    promise.succeed(kexInit)
                }
            case .dhFirstKexPacket(let kexInit, let promise):
                promise.succeed(kexInit)
            case .dhKeyExchange(let serverIdentificationString, let kexInitBuffer, let promise):
                guard let dhReply = try DHServerParameters(
                    parsing: &packet.payload,
                    kexInitBuffer: kexInitBuffer,
                    identificationString: serverIdentificationString
                ) else {
                    promise.fail(SSHError.protocolError)
                    throw SSHError.protocolError
                }
                
                self.context.state = .binaryPackets(.awaitingKeyAcceptance(dhReply, promise))
            case .awaitingKeyAcceptance(let parameters, let promise):
                guard
                    packet.payload.readableBytes == 1,
                    packet.payload.readInteger(as: UInt8.self) == SSHPacketType.newkeys.rawValue
                else {
                    promise.fail(SSHError.keysNotAccepted)
                    throw SSHError.keysNotAccepted
                }
                
                promise.succeed(parameters)
            case .encrypted:
                guard let type = packet.payload.getInteger(at: 0, as: UInt8.self) else {
                    throw SSHError.protocolError
                }
                
                if let handler = self.context.handlers[type] {
                    handler(packet)
                } else {
                    self.context.fallbackHandler(packet)
                }
            }
            
            return .continue
        }
    }
    
    func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        buffer.moveReaderIndex(to: buffer.readableBytes)
        return .continue
    }
}

enum CompressionAlgorithm: String, Hashable {
    case none
    
    func compress(_ buffer: inout ByteBuffer) {
        switch self {
        case .none:
            return
        }
    }
    
    func decompress(_ buffer: inout ByteBuffer) {
        switch self {
        case .none:
            return
        }
    }
}

enum EncryptionMethod: String, Hashable {
    case aes128ctr = "aes128-ctr"
    case aes192ctr = "aes192-ctr"
    case aes256ctr = "aes256-ctr"
    
    var blockSize: Int {
        Int(AES_BLOCK_SIZE)
    }
    
    var ivSize: Int {
        Int(AES_BLOCK_SIZE)
    }
    
    var keySize: Int {
        switch self {
        case .aes128ctr:
            return 128 / 8
        case .aes192ctr:
            return 192 / 8
        case .aes256ctr:
            return 256 / 8
        }
    }
}

enum MessageAuthenticationAlgorithm: String, Hashable {
    case none
    case hmacSHA256 = "hmac-sha2-256"
    case hmacSHA512 = "hmac-sha2-512"
    
    var hashSize: Int {
        switch self {
        case .none:
            return 0
        case .hmacSHA256:
            return SHA256.byteCount
        case .hmacSHA512:
            return SHA512.byteCount
        }
    }
    
    func hash(buffer: UnsafeRawBufferPointer, sequenceNumber: UInt32, integrityKey: [UInt8]) -> [UInt8] {
        switch self {
        case .none:
            return []
        case .hmacSHA256:
            return hashSHA256(buffer: buffer, sequenceNumber: sequenceNumber, integrityKey: integrityKey)
        case .hmacSHA512:
            return hashSHA512(buffer: buffer, sequenceNumber: sequenceNumber, integrityKey: integrityKey)
        }
    }

    private func hashSHA256(buffer: UnsafeRawBufferPointer, sequenceNumber: UInt32, integrityKey: [UInt8]) -> [UInt8] {
        var hmac = HMAC<SHA256>(key: .init(data: integrityKey))
        withUnsafeBytes(of: sequenceNumber.bigEndian) { buffer in
            assert(buffer.count == 4)
            hmac.update(data: buffer)
        }
        hmac.update(data: buffer)
        return Array(hmac.finalize())
    }

    private func hashSHA512(buffer: UnsafeRawBufferPointer, sequenceNumber: UInt32, integrityKey: [UInt8]) -> [UInt8] {
        var hmac = HMAC<SHA512>(key: .init(data: integrityKey))
        withUnsafeBytes(of: sequenceNumber.bigEndian) { buffer in
            assert(buffer.count == 4)
            hmac.update(data: buffer)
        }
        hmac.update(data: buffer)
        return Array(hmac.finalize())
    }
}

struct SSHPacket {
    let length: UInt32
    let paddingLength: UInt8
    var payload: ByteBuffer
    let padding: ByteBuffer
}

enum KeyExchangeAlgorithm: String, Hashable {
    case dhGroup14Sha1 = "diffie-hellman-group14-sha1"
    
    var hashSize: Int {
        switch self {
        case .dhGroup14Sha1:
            return 20 // SHA1 hashes are 20 bytes long
        }
    }
}

enum ServerKeyExchangeMethod: String, Hashable {
    case sshRsa = "ssh-rsa"
    
    func sign(_ input: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 20)
        CCryptoBoringSSL_SHA1(
            input,
            input.count,
            &output
        )
        return output
    }
    
    func verifyExchangeHash(clientHash: [UInt8], server: DHServerParameters) throws -> Bool {
        var hashSignature = server.signature
        
        guard hashSignature.readSSH2String() == self.rawValue else {
            throw SSHError.notRSA
        }
        
        guard let serverSignature = hashSignature.readSSH2Bytes() else {
            throw SSHError.protocolError
        }
        
        let context = CCryptoBoringSSL_RSA_new()
        defer { CCryptoBoringSSL_RSA_free(context) }

        guard CCryptoBoringSSL_RSA_set0_key(
            context,
            server.n,
            server.e,
            nil
        ) == 1 else {
            return false
        }
        
        var clientSignature = [UInt8](repeating: 0, count: 20)
        CCryptoBoringSSL_SHA1(clientHash, clientHash.count, &clientSignature)
        
        return CCryptoBoringSSL_RSA_verify(
            NID_sha1,
            clientSignature,
            20,
            serverSignature,
            serverSignature.count,
            context
        ) == 1
    }
}

protocol CertificateFormat {
    var identifier: String { get }
    
    func makeByteBuffer() throws -> EventLoopFuture<ByteBuffer>
}

struct SSHDSS: CertificateFormat {
    let identifier = "ssh-dss"
    
    func makeByteBuffer() throws -> EventLoopFuture<ByteBuffer> {
        fatalError()
    }
}

enum SSHPacketType: UInt8 {
    case disconnect = 1
    case ignore = 2
    case unimplemented = 3
    case debug = 4
    case serviceRequest = 5
    case serviceAccept = 6
    case kexinit = 20
    case newkeys = 21
    case kexdhinit = 30
    case kexdhreply = 31
    case userAuthRequest = 50
    case userAuthFailure = 51
    case userAuthSuccess = 52
    case userAuthBanner = 53
}

struct SSHRSA: CertificateFormat {
    let identifier = "ssh-rsa"
    
    func makeByteBuffer() throws -> EventLoopFuture<ByteBuffer> {
        fatalError()
    }
}

extension ByteBuffer {
    mutating func decryptAndMac(context: SSHStateContext, sequenceNumber: UInt32) throws {
        let macSize = context.serverMacSize
        guard readableBytes > macSize else {
            throw SSHError.protocolError
        }
        
        let mac = self.getBytes(at: readableBytes - macSize, length: macSize) ?? []
        self.moveWriterIndex(to: writerIndex - macSize)
        
        try self.withUnsafeMutableReadableBytes { buffer in
            try context.decrypt(buffer)
            
            if macSize > 0, let verifyDigest = context.verifyDigest {
                let payload = UnsafeRawBufferPointer(
                    start: buffer.baseAddress,
                    count: buffer.count
                )
                guard verifyDigest(payload, sequenceNumber, mac) else {
                    throw SSHError.invalidMac
                }
            }
        }
    }
    
    mutating func readSSHPacket(context: SSHStateContext, sequenceNumber: UInt32) throws -> SSHPacket? {
        try decryptAndMac(context: context, sequenceNumber: sequenceNumber)
        
        let baseIndex = readerIndex
        
        guard
            let length: UInt32 = readInteger(),
            let paddingLength: UInt8 = readInteger()
        else {
            self.moveReaderIndex(to: baseIndex)
            return nil
        }
        
        guard length <= 16_000_000, paddingLength >= 4 else {
            throw SSHError.unreasonablePacketLength
        }
        
        guard
            let payload = readSlice(length: Int(length) - Int(paddingLength) - 1),
            let padding = readSlice(length: Int(paddingLength))
        else {
            self.moveReaderIndex(to: baseIndex)
            return nil
        }
        
        return SSHPacket(length: length, paddingLength: paddingLength, payload: payload, padding: padding)
    }
    
    mutating func readStringUntilCRLN() -> String? {
        let stringLength = self.withUnsafeReadableBytes { buffer -> Int? in
            // Stop 1 before, because we need BOTH CR and LF
            for i in 0..<buffer.count - 1 {
                if buffer[i] == 0x0d && buffer[i + 1] == 0x0a {
                    return i
                }
            }
            
            return nil
        }
        
        if let stringLength = stringLength {
            let string = self.readString(length: stringLength)
            moveReaderIndex(forwardBy: 2)
            
            return string
        } else {
            return nil
        }
    }
    
    mutating func writeNameList<S: Sequence>(_ strings: S) where S.Element == String {
        let strings = strings.joined(separator: ",")
        
        writeInteger(UInt32(strings.count))
        writeString(strings)
    }
    
    mutating func readNameList() -> [Substring]? {
        guard
            let length: UInt32 = readInteger(),
            let list = readString(length: Int(length))
        else {
            return nil
        }
        
        return list.split(separator: ",")
    }
}

enum SSHError: String, Error, CustomDebugStringConvertible {
    case unreasonablePacketLength, protocolError, disconnected, keysNotAccepted, keyExchangeMismatch, authenticationFailure, passwordChangeRequested, internalError, notRSA, packetSize, invalidMac
    
    var debugDescription: String {
        rawValue
    }
}

extension Sequence {
    func mapString<T>(_ transform: (String) -> T) -> [T] where Element == Substring {
        map { substring in
            return transform(String(substring))
        }
    }
    
    func compactMapString<T>(_ transform: (String) -> T?) -> [T] where Element == Substring {
        compactMap { substring in
            return transform(String(substring))
        }
    }
}
