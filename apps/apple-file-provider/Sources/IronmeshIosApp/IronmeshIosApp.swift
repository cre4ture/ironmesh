import AppleCore
import FileProvider
import SwiftUI

@main
struct IronmeshIosApp: App {
    @StateObject private var model = IronmeshBrowserModel()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("Status") {
                        Text(model.statusText)
                            .font(.footnote)
                    }

                    Section("Root Items") {
                        if model.items.isEmpty {
                            Text("No items loaded yet.")
                                .foregroundStyle(.secondary)
                        }

                        ForEach(model.items, id: \.identifier.serialized) { item in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.displayName)
                                Text(item.identifier.serialized)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .navigationTitle("IronMesh iOS")
                .toolbar {
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        Button("Register Domain") {
                            model.registerDomain()
                        }
                        Button("Refresh") {
                            model.refresh()
                        }
                    }
                }
            }
            .task {
                model.refresh()
            }
        }
    }
}
