import Foundation
import NIO
import Crypto
import CCryptoBoringSSL

// TODO: Free memory everywhere using class wrappers w/ deinit blocks
// TODO: Get rid of manual allocation
// TODO: Major code cleanups, this code is shit, although, to be fair, most SSH libs I've seen are more shit

private let version = "1.0.0"

let generator2: [UInt8] = [ 0x02 ]
let dh14p: [UInt8] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
]

public enum SSHKeyGenerator {
    case generate
    case premade(UnsafeMutablePointer<DH>)
    
    func makeDHContext() -> UnsafeMutablePointer<DH> {
        switch self {
        case .generate:
            return generateDHContext()
        case .premade(let context):
            return context
        }
    }
    
    private func generateDHContext() -> UnsafeMutablePointer<DH> {
        let dhContext = CCryptoBoringSSL_DH_new()!
        let bnContext = CCryptoBoringSSL_BN_CTX_new()
        defer { CCryptoBoringSSL_BN_CTX_free(bnContext) }
        
        dhContext.pointee.p = CCryptoBoringSSL_BN_bin2bn(dh14p, dh14p.count, nil)
        dhContext.pointee.g = CCryptoBoringSSL_BN_bin2bn(generator2, generator2.count, nil)
        dhContext.pointee.priv_key = CCryptoBoringSSL_BN_new()
        dhContext.pointee.pub_key = CCryptoBoringSSL_BN_new()
        
        guard
            CCryptoBoringSSL_BN_rand(dhContext.pointee.priv_key, 256 * 8 - 1, 0, /*-1*/BN_RAND_BOTTOM_ANY) == 1,
            CCryptoBoringSSL_BN_mod_exp(dhContext.pointee.pub_key, dhContext.pointee.g, dhContext.pointee.priv_key, dhContext.pointee.p, bnContext) == 1
        else {
            fatalError()
        }
        
        return dhContext
    }
}

public final class SSHSession {
    let channel: Channel
    let context: SSHStateContext
    var senderId: UInt32 = 0
    
    init(channel: Channel, context: SSHStateContext) {
        self.channel = channel
        self.context = context
    }
    
    public static func connect(
        onChannel channel: Channel,
        keys: SSHKeyGenerator = .generate
    ) throws -> EventLoopFuture<SSHSession> {
        let promise = channel.eventLoop.makePromise(of: String.self)
        let context = SSHStateContext(
            promise: promise,
            allocator: channel.allocator,
            keys: keys
        )
        
        return channel.pipeline.addHandlers(
            MessageToByteHandler(SSHPacketEncoder(context: context)),
            ByteToMessageHandler(SSHPacketDecoder(context: context))
        ).flatMap {
            let session = SSHSession(channel: channel, context: context)
            return session.handshake(
                versionReply: promise.futureResult
            ).map { session }
        }
    }
    
    private func handshake(
        versionReply: EventLoopFuture<String>
    ) -> EventLoopFuture<Void> {
        let packet = SSHClientMessage.versionExchange(self.context.clientParameters.identificationString)
        return channel.writeAndFlush(packet)
            .flatMap { versionReply }
            .flatMap { serverIdentification -> EventLoopFuture<(KeyExchangeInitialization, String)> in
                self.context.serverIdentification = serverIdentification
                
                let promise = self.channel.eventLoop.makePromise(of: KeyExchangeInitialization.self)
                self.context.state = .binaryPackets(.keyExchange(promise))
                return self.channel.writeAndFlush(SSHClientMessage.kexInit(self.context.clientParameters.keyExchangeConfig))
                    .flatMap { promise.futureResult.and(value: serverIdentification) }
        }.flatMapThrowing { serverKeyExchange, serverIdentification -> (KeyExchangeConfig, String, ByteBuffer) in
            let config = try KeyExchangeConfig(client: self.context.clientParameters.keyExchangeConfig, server: serverKeyExchange)
            return (config, serverIdentification, serverKeyExchange.payload)
        }.flatMap { (config, serverIdentification, serverKexInit) -> EventLoopFuture<Void> in
            let promise = self.channel.eventLoop.makePromise(of: DHServerParameters.self)
            self.context.state = .binaryPackets(
                .dhKeyExchange(
                    serverIdentification,
                    kexInitBuffer: serverKexInit,
                    promise
                )
            )
            
            return self.channel.writeAndFlush(
                SSHClientMessage.kexDhInit(self.context.clientParameters)
            ).flatMap {
                promise.futureResult.flatMap { serverParameters -> EventLoopFuture<Void> in
                    do {
                        let params = try DHClientServerParameters(
                            client: self.context.clientParameters,
                            server: serverParameters,
                            config: config
                        )
                        
                        self.context.state = .binaryPackets(.encrypted)
                        return self.channel.writeAndFlush(
                            SSHClientMessage.dhAcceptKeys
                        ).map {
                            let encryption = SSHStateContext.Encryption(
                                clientCipher: config.clientEncryption,
                                clientMac: config.clientMac,
                                params: params
                            )
                            
                            let decryption = SSHStateContext.Decryption(
                                serverCipher: config.serverEncryption,
                                serverMac: config.serverMac,
                                params: params
                            )
                            
                            self.context.encryptConnection(decryptUsing: decryption, encryptUsing: encryption)
                        }
                    } catch {
                        return self.channel.eventLoop.makeFailedFuture(error)
                    }
                }
            }
        }
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        keys: SSHKeyGenerator = .generate
    ) throws -> EventLoopFuture<SSHSession> {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let promise = group.next().makePromise(of: String.self)
        let context = SSHStateContext(
            promise: promise,
            allocator: ByteBufferAllocator(),
            keys: keys
        )
        
        return ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandlers(
                MessageToByteHandler(SSHPacketEncoder(context: context)),
                ByteToMessageHandler(SSHPacketDecoder(context: context))
            )
        }.connect(host: host, port: port).flatMap { channel in
            do {
                return try Self.connect(onChannel: channel)
            } catch {
                return group.next().makeFailedFuture(error)
            }
        }
    }
    
    public func authenticate(username: String, byPassword password: String) -> EventLoopFuture<Void> {
        let promise = self.channel.eventLoop.makePromise(of: SSHPacket.self)
        
        self.context.handlers[.serviceAccept] = promise.accept
        
        return self.channel.writeAndFlush(
            SSHClientMessage.requestService("ssh-userauth")
        ).flatMap {
            promise.futureResult
        }.flatMap { _ in
            self.context.handlers[.serviceAccept] = nil
            return self._serviceAuthenticate(username: username, byPassword: password)
        }
    }
    
    func _serviceAuthenticate(username: String, byPassword password: String) -> EventLoopFuture<Void> {
        let promise = self.channel.eventLoop.makePromise(of: SSHPacket.self)
        
        self.context.handlers[.userAuthSuccess] = promise.accept
        self.context.handlers[.userAuthFailure] = promise.accept
        
        return self.channel.writeAndFlush(
            SSHClientMessage.authenticatePassword(
                username: username,
                password: password
            )
        ).flatMap { promise.futureResult }.flatMapThrowing { packet in
            var payload = packet.payload
            
            switch SSHLoginReply(parsing: &payload) {
            case .success:
                return
            case .failure:
                throw SSHError.authenticationFailure
            case .none:
                throw SSHError.internalError
            }
        }.always { _ in
            self.context.handlers[.userAuthSuccess] = nil
            self.context.handlers[.userAuthFailure] = nil
        }
    }
}

extension EventLoopPromise {
    func accept(_ value: Result<Value, Error>) -> Bool {
        completeWith(value)
        return true
    }
}
