import Foundation

public func normalizedPath(_ path: String) -> String {
    let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return "" }

    let replaced = trimmed.replacingOccurrences(of: "\\", with: "/")
    let parts = replaced.split(separator: "/", omittingEmptySubsequences: true)
    return parts.joined(separator: "/")
}

public extension String {
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

public extension Optional where Wrapped == String {
    var nilIfBlank: String? {
        self?.nilIfBlank
    }
}
