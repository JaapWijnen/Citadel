import NIO


// MARK: - Error types

/// Errors that may be thrown during various `SSHChannel` operations
enum SSHChannelError: Error {
    case unsupported, isClosed, cannotCloseUnopenedChannel
}


// MARK: - Constants/configuration

/// - Note: Normally I'd put these statically on an appropriate type, but I couldn't figure out
///   the best one so I just left them global.

/// Forwarded SSH channel window size.
fileprivate let SSH_CHANNEL_WINDOW_SIZE: UInt32 = 1 << 21 // 2^21 == 2_097_152 == 2MiB

/// Maximum packet size for forwarded SSH channel.
fileprivate let SSH_CHANNEL_MAX_PACKET_SIZE: UInt32 = 1 << 15 // 2^15 == 32_768 == 32KiB

/// Maximum number of bytes to write to a channel at once.
fileprivate let SSH_CHANNEL_MAX_WRITE = Int(SSH_CHANNEL_MAX_PACKET_SIZE) - 64


/// Sigh, Swift needs a `#assert`, as put forth here:
///     https://forums.swift.org/t/compile-time-constant-expressions-for-swift/12879
/// Why can't they focus on this instead of trailing closure syntax?
///
/// For now, this is invoked from `SSHSession.forward()`, which is really not at all preferable,
/// but is the best as can be done at present.
fileprivate let _assert_sanity: Void = { () -> Void in
    /// Make sure the config params are at least minimally sensible.
    /// - TODO: I made some basic assumptions about the requirements of these values.
    ///   If any of the assumptions are wrong, just yank the assertions.
    assert(SSH_CHANNEL_WINDOW_SIZE.nonzeroBitCount == 1, "Window size must be a power of two")
    assert(SSH_CHANNEL_MAX_PACKET_SIZE.nonzeroBitCount == 1, "Max packet size should really be a power of two")
    assert(SSH_CHANNEL_MAX_WRITE + 32 < SSH_CHANNEL_MAX_PACKET_SIZE, "Max write can't be within 32 bytes of the max packet size")
}()


// MARK: - SSHForwardedChannel

/// An NIO-based channel that forwards data over an SSH connection.
internal final class SSHForwardedChannel {
    
    public var isOpen: Bool { self.state != .closed } // `self.state == .open(_)` doesn't work
    
    /// Current channel state and SSH connection control data.
    fileprivate enum State: Equatable {
        case closed
        case open(SSHChannelOpenChannelInfo)
    }
    
    private var state: State
    private let session: SSHSession
    private var _pipeline: ChannelPipeline!
    
    fileprivate let closePromise: EventLoopPromise<Void>
    
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
    
    fileprivate func read(_ data: ByteBuffer) {
        pipeline.fireChannelRead(NIOAny(data))
    }
    
    fileprivate func write(_ outgoingData: ByteBuffer) -> EventLoopFuture<Void> {
        guard case .open(let state) = self.state else {
            return eventLoop.makeFailedFuture(SSHChannelError.isClosed)
        }
        
        var buffer = outgoingData
        var future = eventLoop.makeSucceededFuture(())
        
        while buffer.readableBytes > 0 {
            guard let data = buffer.readSlice(length: Swift.min(SSH_CHANNEL_MAX_WRITE, buffer.readableBytes)) else {
                fatalError("Failure to readSlice(), corrupted ByteBuffer?")
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

/// NIO Channel conformance for `SSHForwardedChannel`. Pretty much just forwards
/// everything to the implementations on the main class.
extension SSHForwardedChannel: Channel, ChannelCore {
    
    // Unsupported operations
    public var localAddress: SocketAddress? { nil }
    public var remoteAddress: SocketAddress? { nil }
    public func localAddress0() throws -> SocketAddress { throw SSHChannelError.unsupported }
    public func remoteAddress0() throws -> SocketAddress { throw SSHChannelError.unsupported }
    public func bind0(to: SocketAddress, promise: EventLoopPromise<Void>?) { promise?.fail(SSHChannelError.unsupported) }
    public func connect0(to: SocketAddress, promise: EventLoopPromise<Void>?) { promise?.fail(SSHChannelError.unsupported) }
    public func triggerUserOutboundEvent0(_: Any, promise: EventLoopPromise<Void>?) { promise?.fail(SSHChannelError.unsupported) }
    public func setOption<O: ChannelOption>(_: O, value: O.Value) -> EventLoopFuture<Void> { eventLoop.makeFailedFuture(SSHChannelError.unsupported) }
    public func getOption<O: ChannelOption>(_: O) -> EventLoopFuture<O.Value> { eventLoop.makeFailedFuture(SSHChannelError.unsupported) }
    
    // NO-OPS
    public func flush0() {}
    public func channelRead0(_ data: NIOAny) {}
    public func read0() {}

    // Accessors
    public var allocator: ByteBufferAllocator { session.channel.allocator }
    public var closeFuture: EventLoopFuture<Void> { closePromise.futureResult }
    public var parent: Channel? { session.channel }
    public var _channelCore: ChannelCore { self }
    public var eventLoop: EventLoop { session.channel.eventLoop }
    public var pipeline: ChannelPipeline { _pipeline }
    
    // State getters
    public var isWritable: Bool { true }
    public var isActive: Bool { true }
    
    /// Registration callback - succeed if open, fail if closed, quite simple really.
    public func register0(promise: EventLoopPromise<Void>?) {
        promise?.completeWith(self.isOpen ? .success(()) : .failure(SSHChannelError.isClosed))
    }
    
    /// Send outoging data
    public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
        write(unwrapData(data)).cascade(to: promise)
    }
    
    /// Close channel
    public func close0(error: Error, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        switch mode {
        case .all:
            self.close().cascade(to: promise)
        case .input, .output:
            promise?.fail(SSHChannelError.unsupported)
        }
    }
    
    /// Handle error
    public func errorCaught0(error: Error) {
        /// - TODO: Maybe log something with a `Logger` if there isn't any more opportune place to catch these?
    }
}

// MARK: - SSHSession fowarding channel creation

/// The type of SSH channel to use for forwarding.
/// - TODO: Is this a correct description?
enum SSHChannelType: String {

    /// TCP/IP forwarding channel
    case tcpIpForward = "tcpip-forward"
    
    /// Direct TCP/IP connection
    case directTcpIp = "direct-tcpip"
}


extension SSHSession {
    /// Crete and configure an `SSHForwardedChannel` of the specified type using
    /// the provided data as the channel-open request.
    internal func openChannel(
        type: SSHChannelType,
        data: ByteBuffer
    ) -> EventLoopFuture<SSHForwardedChannel> {
        let openRequest = SSHChannelRequest(
            channelType: type,
            senderId: senderId,
            windowSize: SSH_CHANNEL_WINDOW_SIZE,
            maxPacketSize: SSH_CHANNEL_MAX_PACKET_SIZE,
            channelData: data
        )
        senderId &+= 1
        
        let promise: EventLoopPromise<SSHChannelOpenChannelInfo> = channel.eventLoop.makePromise()
        
        // ByteBuffer needing mutability is the one and only reason this can't be WAY more elegant
        // (Well, the trinary decision point for the packet type doesn't help either.)
        func handle(packet: Result<SSHPacket, Error>) -> Bool { promise.accept(packet.flatMap { SSHChannelOpenChannelInfo.parseResponse(packet: $0) }) }
        
        self.context.handlers[.channelOpenConfirm] = handle
        self.context.handlers[.channelOpenFailure] = handle
        
        return channel.writeAndFlush(SSHClientMessage.openChannel(openRequest)).flatMap {
            promise.futureResult
        }.map {
            let channel = SSHForwardedChannel(session: self, state: .open($0))
            
            self.context.channels[$0.recipientId] = { [weak channel] in channel?.read($0) }
            return channel
        }
    }
    
    /// Outward-facing interface to channel forwarding.
    public func forward(
        remoteHost: String,
        remotePort: UInt16,
        connectedIpAddress: String,
        connectedPort: UInt16
    ) -> EventLoopFuture<Channel> {
        // Make sure our config params make sense. It's very poor form to potentially assert only here,
        // which may never get called during normal operation, but it seems the best available option
        // for the time being. The assertions should never fire as long as the values are kept reasonable.
        // How sadly convoluted.
        withExtendedLifetime(_assert_sanity, { assert($0 == ()) })
    
        var buffer = channel.allocator.buffer(capacity: 100)
        buffer.writeSSH2String(remoteHost)
        buffer.writeInteger(UInt32(remotePort))
        buffer.writeSSH2String(connectedIpAddress)
        buffer.writeInteger(UInt32(connectedPort))
        
        return openChannel(type: .directTcpIp, data: buffer).map { $0 }
    }
}
