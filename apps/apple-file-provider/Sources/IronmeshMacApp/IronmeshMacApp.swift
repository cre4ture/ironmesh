import AppleCore
import FileProvider
import SwiftUI

@main
struct IronmeshMacApp: App {
    @StateObject private var model = IronmeshBrowserModel()

    var body: some Scene {
        WindowGroup {
            NavigationSplitView {
                List(model.items, id: \.identifier.serialized) { item in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item.displayName)
                        Text(item.identifier.serialized)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                .navigationSplitViewColumnWidth(min: 280, ideal: 320)
            } detail: {
                VStack(alignment: .leading, spacing: 16) {
                    Text("IronMesh macOS")
                        .font(.largeTitle)
                        .bold()
                    Text(model.statusText)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    HStack {
                        Button("Register Domain") {
                            model.registerDomain()
                        }
                        Button("Refresh Root") {
                            model.refresh()
                        }
                    }
                    Spacer()
                }
                .padding(24)
            }
            .task {
                model.refresh()
            }
        }
    }
}
