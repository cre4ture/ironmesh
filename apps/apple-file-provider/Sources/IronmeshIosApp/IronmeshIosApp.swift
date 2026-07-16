import AppleCore
import FileProvider
import SwiftUI
import UIKit
import WebKit

@main
struct IronmeshIosApp: App {
    private enum AppSection: Hashable {
        case library
        case galleryMap
    }

    @StateObject private var model = IronmeshBrowserModel()
    @State private var isShowingScanner = false
    @State private var selectedSection: AppSection = .library

    var body: some Scene {
        WindowGroup {
            TabView(selection: $selectedSection) {
                NavigationStack {
                    Form {
                        Section("Status") {
                            if model.isBusy {
                                ProgressView()
                            }

                            Text(model.statusText)
                                .font(.footnote)
                        }

                        Section("Active Connection") {
                            TextEditor(text: $model.connectionInput)
                                .frame(minHeight: 96)
                                .font(.body.monospaced())

                            Button("Save Connection") {
                                model.saveConnectionInput()
                            }
                            .disabled(model.isBusy)

                            Button("Paste Connection") {
                                pasteConnectionInput()
                            }
                            .disabled(model.isBusy)

                            Button("Register Domain") {
                                model.registerDomain()
                            }
                            .disabled(model.isBusy)

                            Button("Refresh Root") {
                                model.refresh()
                            }
                            .disabled(model.isBusy)
                        }

                        Section("Device Identity") {
                            if let deviceID = model.enrolledDeviceID?.nilIfBlank {
                                Text("Device ID: \(deviceID)")
                                if let label = model.enrolledDeviceLabel?.nilIfBlank {
                                    Text("Label: \(label)")
                                }
                            } else {
                                Text("This device is not enrolled yet.")
                                    .foregroundStyle(.secondary)
                            }

                            TextField(
                                "Device Label",
                                text: Binding(
                                    get: { model.deviceLabelInput },
                                    set: { model.updateDeviceLabelInput($0) }
                                )
                            )
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        }

                        Section("Bootstrap Claim or Bundle") {
                            TextEditor(
                                text: Binding(
                                    get: { model.bootstrapInput },
                                    set: { model.updateBootstrapInput($0) }
                                )
                            )
                            .frame(minHeight: 140)
                            .font(.body.monospaced())

                            Button("Paste Bootstrap") {
                                pasteBootstrapInput()
                            }
                            .disabled(model.isBusy)

                            Button("Scan QR") {
                                isShowingScanner = true
                            }
                            .disabled(model.isBusy)

                            Button("Clear Bootstrap") {
                                model.updateBootstrapInput("")
                            }
                            .disabled(model.isBusy)

                            Button("Enroll Device") {
                                model.enrollDevice()
                            }
                            .disabled(model.isBusy)

                            Button("Clear Device Identity") {
                                model.clearDeviceEnrollment()
                            }
                            .disabled(model.isBusy || !model.hasEnrolledDevice)
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
                }
                .tabItem {
                    Label("Library", systemImage: "books.vertical")
                }
                .tag(AppSection.library)

                NavigationStack {
                    Group {
                        if let url = model.galleryMapURL {
                            GalleryMapWebView(url: url)
                        } else {
                            VStack(spacing: 16) {
                                if model.isStartingWebUi {
                                    ProgressView()
                                }
                                Text("Open the shared gallery map directly inside the iOS app.")
                                    .multilineTextAlignment(.center)
                                    .foregroundStyle(.secondary)
                                Button("Open Gallery Map") {
                                    model.startGalleryMap(force: true)
                                }
                                .disabled(model.isStartingWebUi)
                            }
                            .padding(24)
                        }
                    }
                    .navigationTitle("Gallery Map")
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            if model.isStartingWebUi {
                                ProgressView()
                            } else {
                                Button("Reload") {
                                    model.startGalleryMap(force: true)
                                }
                            }
                        }
                    }
                }
                .tabItem {
                    Label("Gallery Map", systemImage: "map")
                }
                .tag(AppSection.galleryMap)
            }
            .task {
                model.refresh()
            }
            .task(id: selectedSection) {
                if selectedSection == .galleryMap {
                    model.startGalleryMap()
                }
            }
            .sheet(isPresented: $isShowingScanner) {
                IronmeshBootstrapScannerSheet { scannedValue in
                    model.updateBootstrapInput(scannedValue)
                    isShowingScanner = false
                }
            }
        }
    }

    private func pasteConnectionInput() {
        guard let value = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            model.statusText = "Clipboard does not contain text."
            return
        }
        model.connectionInput = value
    }

    private func pasteBootstrapInput() {
        guard let value = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            model.statusText = "Clipboard does not contain text."
            return
        }
        model.updateBootstrapInput(value)
    }
}

private struct GalleryMapWebView: UIViewRepresentable {
    let url: URL

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView(frame: .zero)
        webView.allowsBackForwardNavigationGestures = true
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        if webView.url != url {
            webView.load(URLRequest(url: url))
        }
    }
}
