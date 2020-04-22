import NIO

/// The layout of a channel request packet.
struct SSHChannelRequest {
    let channelType: SSHChannelType
    let senderId: UInt32
    let windowSize: UInt32
    let maxPacketSize: UInt32
    let channelData: ByteBuffer
}

/// The layout of a packet returned from a successful channel request
struct SSHChannelOpenChannelInfo: Equatable {
    let recipientId: UInt32
    let senderId: UInt32
    var windowSize: UInt32
    let maxPacketSize: UInt32
    let channelData: ByteBuffer
 
    /// Parse the packet format from an input buffer if possible.
    static func from(payload: inout ByteBuffer) -> Result<Self, Error> {
        guard
            let recip: UInt32 = payload.readInteger(),
            let sender: UInt32 = payload.readInteger(),
            let winSize: UInt32 = payload.readInteger(),
            let maxPktSize: UInt32 = payload.readInteger(),
            let data = payload.readSlice(length: payload.readableBytes)
        else {
            return .failure(SSHError.protocolError)
        }
        return .success(.init(recipientId: recip, senderId: sender, windowSize: winSize, maxPacketSize: maxPktSize, channelData: data))
    }
    
    /// Parse the provided buffer to determine whether the packet it represents,
    /// if any, is channel open success, channel open failure, or anything else,
    /// including empty. For success, parse the channel info packet and return
    /// it as a success result. For failure, parse the error reason packet and
    /// return it as a failure result. For anything else, or if any error occurs
    /// in the other cases, return a protocol error failure.
    ///
    /// - Note: Why put this method here instead of keeping the
    ///   `SSHChannelResponse` type, or at least using it as a namespace for
    ///   this behavior? Answer: This type is the "positive"/"success" packet,
    ///   which is the place from where actions should generally be sourced when
    ///   practical and appropriate. From a code architecture standpoint, the
    ///   "failure" packet is not only a failure condition but also actually
    ///   conforms to `Error`; such types are not traditionally first- class
    ///   types in terms of behavior, but rather are usually auxiliary helpers
    ///   and information couriers. Additionally, this design makes the failure
    ///   case of our `Result<>` an instance of the failure packet itself, even
    ///   when parsing it succeeds, while _this_ structure is the success case
    ///   for all paths. Accordingly, we have reason (if you like) to conclude
    ///   that this type is sufficiently "authoritative" not to need an
    ///   enclosing "generic response kind" namespace; there is nothing _other_
    ///   than the two packet types that might be placed therein.
    ///
    /// - Note: The `Result<>` we return has generic `Error` as its failure type
    ///   instead of the failure packet simply because it makes life easier when
    ///   chaining actions elsewhere.
    static func parseResponse(packet: SSHPacket) -> Result<Self, Error> {
        var payload = packet.payload // copy payload to `var` because `ByteBuffer` is awful that way
        
        // Read packet discriinator, convert to packet type if possible. (Doing this as a single step allows
        // the compiler to infer `UInt8` as the integer type to read so we don't have to specify it.)
        let type = payload.readInteger().flatMap { SSHPacketType(rawValue: $0) }
        
        switch type {
            case .channelOpenConfirm: return Self.from(payload: &payload) // confirm; try parsing success and return result
            case .channelOpenFailure: return SSHChannelOpenFailure.from(payload: &payload).flatMap { .failure($0) } // parse fail and make it an error
            default: return .failure(SSHError.protocolError) // some other packet, or no integer value, return protocol error
        }
    }
}

/// The layout of a packet returned from a failed channel request
struct SSHChannelOpenFailure: Error, Equatable {
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
    
    /// Parse the packet format from an input buffer if possible.
    static func from(payload: inout ByteBuffer) -> Result<Self, Error> {
        guard
            let recip: UInt32 = payload.readInteger(),
            let reason: UInt32 = payload.readInteger(),
            let desc = payload.readSSH2String(),
            let lang = payload.readSSH2String()
        else {
            return .failure(SSHError.protocolError)
        }
        return .success(.init(recipientId: recip, reason: Reason(rawValue: reason), description: desc, language: lang))
    }
}
