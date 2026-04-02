import Foundation

public protocol AppleManualCBridge: AppleRustBridge {
    func operation(_ operation: AppleBridgeOperation, on reference: AppleBridgeItemReference?) throws
}

public extension AppleManualCBridge {
    func operation(_ operation: AppleBridgeOperation, on reference: AppleBridgeItemReference?) throws {
        _ = operation
        _ = reference
    }
}

