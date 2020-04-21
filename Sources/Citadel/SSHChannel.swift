import NIO

final class SSHForwardedChannel {
    enum State {
        case unopened, closed
        case open(SSHChannelResponse.Success)
    }
    
    let session: SSHSession
    private var state: State
    public var isOpen: Bool {
        switch state {
        case .open:
            return true
        case .unopened, .closed:
            return false
        }
    }
    fileprivate let closePromise: EventLoopPromise<Void>
    fileprivate private(set) var _pipeline: ChannelPipeline!
    
    fileprivate init(session: SSHSession, state: State) {
        self.session = session
        self.state = state
        self.closePromise = session.channel.eventLoop.makePromise()
        
        self._pipeline = ChannelPipeline(channel: self)
    }
    
    fileprivate func close() -> EventLoopFuture<Void> {
        switch state {
        case .open(let state):
            self.state = .closed
            eventLoop.execute {
                // Remove pipeline handlers
                self.closePromise.succeed(())
            }
            
            return session.channel.writeAndFlush(
                SSHClientMessage.closeChannel(state.recipientId)
            )
        default:
            return eventLoop.makeFailedFuture(SSHChannelError.cannotCloseUnopenedChannel)
        }
    }
    
    func read(_ data: ByteBuffer) {
        pipeline.fireChannelRead(NIOAny(data))
    }
    
    fileprivate func write(_ data: ByteBuffer) -> EventLoopFuture<Void> {
        guard case .open(let state) = state else {
            return eventLoop.makeFailedFuture(SSHChannelError.isClosed)
        }
        
        var data = data
        var future = eventLoop.makeSucceededFuture(())
        
        while data.readableBytes > 0 {
            guard
                let data = data.readSlice(length: min(32_700, data.readableBytes))
            else {
                return session.channel.eventLoop.makeSucceededFuture(())
            }
        
            future = future.flatMap {
                self.session.channel.writeAndFlush(
                    SSHClientMessage.channelSend(channel: state.recipientId, data: data)
                )
            }
        }
        
        return future
    }
}

enum SSHChannelError: Error {
    case unsupported, isClosed, cannotCloseUnopenedChannel
}

extension SSHForwardedChannel: Channel, ChannelCore {
    func localAddress0() throws -> SocketAddress {
        throw SSHChannelError.unsupported
    }
    
    func remoteAddress0() throws -> SocketAddress {
        throw SSHChannelError.unsupported
    }
    
    func register0(promise: EventLoopPromise<Void>?) {
        guard isOpen else {
            promise?.fail(SSHChannelError.isClosed)
            return
        }
        
        promise?.succeed(())
    }
    
    func bind0(to: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(SSHChannelError.unsupported)
    }
    
    func connect0(to: SocketAddress, promise: EventLoopPromise<Void>?) {
        promise?.fail(SSHChannelError.unsupported)
    }
    
    func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        write(unwrapData(data)).cascade(to: promise)
    }
    
    // NO-OPS
    func flush0() { }
    func channelRead0(_ data: NIOAny) { }
    func errorCaught0(error: Error) { }
    func read0() {}
    
    func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        switch mode {
        case .all:
            self.close().cascade(to: promise)
        case .input, .output:
            promise?.fail(SSHChannelError.unsupported)
        }
    }
    
    func triggerUserOutboundEvent0(_ event: Any, promise: EventLoopPromise<Void>?) {
        promise?.fail(SSHChannelError.unsupported)
    }
    
    var allocator: ByteBufferAllocator { session.channel.allocator }
    var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    
    var pipeline: ChannelPipeline { _pipeline }
    var localAddress: SocketAddress? { nil }
    var remoteAddress: SocketAddress? { nil }
    
    var parent: Channel? { session.channel }
    
    func setOption<Option>(_ option: Option, value: Option.Value) -> EventLoopFuture<Void> where Option : ChannelOption {
        return eventLoop.makeFailedFuture(SSHChannelError.unsupported)
    }
    
    func getOption<Option>(_ option: Option) -> EventLoopFuture<Option.Value> where Option : ChannelOption {
        return eventLoop.makeFailedFuture(SSHChannelError.unsupported)
    }
    
    var isWritable: Bool { true }
    var isActive: Bool { true }
    var _channelCore: ChannelCore { self }
    var eventLoop: EventLoop { session.channel.eventLoop }
}

extension SSHSession {
    internal func openChannel(
        type: SSHChannelType,
        data: ByteBuffer
    ) -> EventLoopFuture<SSHForwardedChannel> {
        let openRequest = SSHChannelRequest(
            channelType: type,
            senderId: senderId,
            windowSize: (2*1024*1024),
            maxPacketSize: 32768,
            channelData: data
        )
        
        senderId = senderId &+ 1
        
        let promise: EventLoopPromise<SSHChannelResponse> = channel.eventLoop.makePromise()
        
        func handle(packet: Result<SSHPacket, Error>) -> Bool {
            switch packet {
            case .success(let packet):
                guard let response = SSHChannelResponse(parsing: packet) else {
                    promise.fail(SSHError.protocolError)
                    return true
                }
                promise.succeed(response)
            case .failure(let error):
                promise.fail(error)
            }
            
            return true
        }
        
        self.context.handlers[.channelOpenConfirm] = handle
        self.context.handlers[.channelOpenFailure] = handle
        
        return channel.writeAndFlush(SSHClientMessage.openChannel(openRequest)).flatMap {
            promise.futureResult
        }.flatMapThrowing { result in
            switch result {
            case .success(let success):
                let channel = SSHForwardedChannel(
                    session: self,
                    state: .open(success)
                )
                self.context.channels[success.recipientId] = { [weak channel] buffer in
                    channel?.read(buffer)
                }
                
                return channel
            case .failure(let failure):
                throw failure
            }
        }
    }
    
    func forward(
        remoteHost: String,
        remotePort: UInt16,
        connectedIpAddress: String,
        connectedPort: UInt16
    ) -> EventLoopFuture<SSHForwardedChannel> {
        var buffer = channel.allocator.buffer(capacity: 100)
        buffer.writeSSH2String(remoteHost)
        buffer.writeInteger(UInt32(remotePort))
        buffer.writeSSH2String(connectedIpAddress)
        buffer.writeInteger(UInt32(connectedPort))
        
        return openChannel(type: .directTcpIp, data: buffer).map { channel in
            return channel
        }
    }
}

enum SSHChannelType: String {
    case tcpIpForward = "tcpip-forward"
    case directTcpIp = "direct-tcpip"
}

struct SSHChannelRequest {
    let channelType: SSHChannelType
    let senderId: UInt32
    let windowSize: UInt32
    let maxPacketSize: UInt32
    let channelData: ByteBuffer
}

struct SSHChannelGlobalRequest {
    let channelType: SSHChannelType
    let wantsReply: Bool
    let data: ByteBuffer
}

enum SSHChannelResponse {
    struct Success {
        let recipientId: UInt32
        let senderId: UInt32
        let windowSize: UInt32
        let maxPacketSize: UInt32
        let channelData: ByteBuffer
        
        init?(parsing payload: inout ByteBuffer) {
            guard
                let recipientId = payload.readInteger(as: UInt32.self),
                let senderId = payload.readInteger(as: UInt32.self),
                let windowSize = payload.readInteger(as: UInt32.self),
                let maxPacketSize = payload.readInteger(as: UInt32.self),
                let data = payload.readSlice(length: payload.readableBytes)
            else {
                return nil
            }
            
            self.recipientId = recipientId
            self.senderId = senderId
            self.windowSize = windowSize
            self.maxPacketSize = maxPacketSize
            self.channelData = data
        }
    }
    
    struct Failure: Error {
        enum Reason: UInt32 {
            case prohibited = 1
            case connectFailed = 2
            case unknownChannelType = 3
            case resourceShortage = 4
        }
        
        let recipientId: UInt32
        let reason: Reason?
        let description: String
        let language: String
        
        init?(parsing payload: inout ByteBuffer) {
            guard
                let recipientId = payload.readInteger(as: UInt32.self),
                let reason = payload.readInteger(as: UInt32.self),
                let description = payload.readSSH2String(),
                let language = payload.readSSH2String()
            else {
                return nil
            }
            
            self.recipientId = recipientId
            self.reason = Reason(rawValue: reason)
            self.description = description
            self.language = language
        }
    }
    
    case success(Success)
    case failure(Failure)
    
    init?(parsing packet: SSHPacket) {
        var payload = packet.payload
        
        switch payload.readInteger(as: UInt8.self) {
        case SSHPacketType.channelOpenConfirm.rawValue:
            guard let result = Success(parsing: &payload) else {
                return nil
            }
            
            self = .success(result)
        case SSHPacketType.channelOpenFailure.rawValue:
            guard let result = Failure(parsing: &payload) else {
                return nil
            }
            
            self = .failure(result)
        default:
            return nil
        }
    }
}
