import AppleCore
import FileProvider
import SwiftUI
import UIKit

@main
struct IronmeshIosApp: App {
    @StateObject private var model = IronmeshBrowserModel()
    @State private var isShowingScanner = false

    var body: some Scene {
        WindowGroup {
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
                                set: { model.deviceLabelInput = $0 }
                            )
                        )
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    }

                    Section("Bootstrap Claim or Bundle") {
                        TextEditor(
                            text: Binding(
                                get: { model.bootstrapInput },
                                set: { model.bootstrapInput = $0 }
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
                            model.bootstrapInput = ""
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
                .onDisappear {
                    model.updateDeviceLabelInput(model.deviceLabelInput)
                    model.updateBootstrapInput(model.bootstrapInput)
                }
            }
            .task {
                model.refresh()
            }
            .sheet(isPresented: $isShowingScanner) {
                IronmeshBootstrapScannerSheet { scannedValue in
                    model.bootstrapInput = scannedValue
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
        model.bootstrapInput = value
    }
}
