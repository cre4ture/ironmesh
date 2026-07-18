import XCTest
@testable import AppleCore

final class AppleLatestRequestCoordinatorTests: XCTestCase {
    func testContextResetRejectsOlderRequest() {
        var coordinator = AppleLatestRequestCoordinator()
        let oldRequest = coordinator.begin()

        coordinator.invalidate()

        XCTAssertFalse(coordinator.isCurrent(oldRequest))
        XCTAssertFalse(coordinator.complete(oldRequest))
        XCTAssertFalse(coordinator.hasCurrentRequest)
    }

    func testNewerRequestSupersedesOlderRequest() {
        var coordinator = AppleLatestRequestCoordinator()
        let oldRequest = coordinator.begin()
        let newRequest = coordinator.begin()

        XCTAssertFalse(coordinator.isCurrent(oldRequest))
        XCTAssertTrue(coordinator.isCurrent(newRequest))
    }

    func testOnlyCurrentCompletionClearsLoadingState() {
        var coordinator = AppleLatestRequestCoordinator()
        let oldRequest = coordinator.begin()
        let newRequest = coordinator.begin()

        XCTAssertFalse(coordinator.complete(oldRequest))
        XCTAssertTrue(coordinator.hasCurrentRequest)

        XCTAssertTrue(coordinator.complete(newRequest))
        XCTAssertFalse(coordinator.hasCurrentRequest)
    }
}
