import Foundation

public enum AppleConnectionRoutePathKind: Hashable, Sendable, Codable {
    case directHTTPS
    case directQUIC
    case relayTunnel
    case unknown(String)

    public init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        switch value {
        case "direct_https":
            self = .directHTTPS
        case "direct_quic":
            self = .directQUIC
        case "relay_tunnel":
            self = .relayTunnel
        default:
            self = .unknown(value)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .directHTTPS:
            return "direct_https"
        case .directQUIC:
            return "direct_quic"
        case .relayTunnel:
            return "relay_tunnel"
        case .unknown(let value):
            return value
        }
    }

    public var displayName: String {
        switch self {
        case .directHTTPS:
            return "Direct HTTPS"
        case .directQUIC:
            return "Direct QUIC"
        case .relayTunnel:
            return "Relay tunnel"
        case .unknown(let value):
            return value.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    public var isDirect: Bool {
        self == .directHTTPS || self == .directQUIC
    }
}

public struct AppleConnectionRouteEndpoint: Codable, Equatable, Identifiable, Sendable {
    public var index: Int
    public var pathKind: AppleConnectionRoutePathKind
    public var locator: String
    public var bootstrapRank: Int
    public var targetNodeId: String?
    public var active: Bool
    public var score: Double
    public var ewmaLatencyMs: Double?
    public var ewmaThroughputBytesPerSec: Double?
    public var consecutiveFailures: UInt32
    public var totalFailures: UInt64
    public var totalSuccesses: UInt64
    public var lastMeasurementUnixMs: UInt64?
    public var lastSuccessUnixMs: UInt64?
    public var lastFailureUnixMs: UInt64?
    public var circuitOpenUntilUnixMs: UInt64?
    public var backgroundProbeInFlight: Bool
    public var lastBackgroundProbeUnixMs: UInt64?
    public var lastError: String?

    public var id: Int { index }

    public func isCoolingDown(atUnixMs timestamp: UInt64) -> Bool {
        guard let circuitOpenUntilUnixMs else {
            return false
        }
        return circuitOpenUntilUnixMs > timestamp
    }
}

public struct AppleConnectionRouteSnapshot: Codable, Equatable, Sendable {
    public var generatedAtUnixMs: UInt64
    public var activeIndex: Int?
    public var rankedIndices: [Int]
    public var endpoints: [AppleConnectionRouteEndpoint]

    public var activeEndpoint: AppleConnectionRouteEndpoint? {
        if let activeIndex,
           let endpoint = endpoints.first(where: { $0.index == activeIndex }) {
            return endpoint
        }
        return endpoints.first(where: \.active)
    }

    public var rankedEndpoints: [AppleConnectionRouteEndpoint] {
        let endpointsByIndex = endpoints.reduce(into: [Int: AppleConnectionRouteEndpoint]()) {
            if $0[$1.index] == nil {
                $0[$1.index] = $1
            }
        }
        var seen = Set<Int>()
        var result = rankedIndices.compactMap { index -> AppleConnectionRouteEndpoint? in
            guard seen.insert(index).inserted else {
                return nil
            }
            return endpointsByIndex[index]
        }
        let remaining = endpoints
            .filter { seen.insert($0.index).inserted }
            .sorted { $0.index < $1.index }
        result.append(contentsOf: remaining)
        return result
    }

    public var directEndpointCount: Int {
        endpoints.filter { $0.pathKind.isDirect }.count
    }

    public var relayEndpointCount: Int {
        endpoints.filter { $0.pathKind == .relayTunnel }.count
    }
}
