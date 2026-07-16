import AVFoundation
import SwiftUI
import UIKit

struct IronmeshBootstrapScannerSheet: View {
    @Environment(\.dismiss) private var dismiss

    let onCodeScanned: (String) -> Void

    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
#if targetEnvironment(simulator)
                VStack(spacing: 16) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 48))
                    Text("QR Scanning Requires a Camera")
                        .font(.headline)
                    Text("The simulator does not provide a camera feed. Paste the bootstrap claim or bundle instead.")
                        .font(.body)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                .padding(24)
#else
                IronmeshBootstrapScannerView(
                    onCodeScanned: { value in
                        onCodeScanned(value)
                    },
                    onError: { message in
                        errorMessage = message
                    }
                )
#endif
            }
            .navigationTitle("Scan Bootstrap QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .overlay(alignment: .bottom) {
                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .multilineTextAlignment(.center)
                        .padding()
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
                        .padding()
                }
            }
        }
    }
}

#if !targetEnvironment(simulator)
private struct IronmeshBootstrapScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void
    let onError: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        ScannerViewController(
            onCodeScanned: onCodeScanned,
            onError: onError
        )
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {
    }
}

@MainActor
private final class ScannerViewController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    private let captureSession = AVCaptureSession()
    private let onCodeScanned: (String) -> Void
    private let onError: (String) -> Void
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasStartedSession = false
    private var hasReportedCode = false

    init(
        onCodeScanned: @escaping (String) -> Void,
        onError: @escaping (String) -> Void
    ) {
        self.onCodeScanned = onCodeScanned
        self.onError = onError
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if hasStartedSession, !captureSession.isRunning {
            captureSession.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession.isRunning {
            captureSession.stopRunning()
        }
    }

    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        _ = output
        _ = connection

        guard let value = metadataObjects
            .compactMap({ $0 as? AVMetadataMachineReadableCodeObject })
            .first?
            .stringValue?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else {
            return
        }

        Task { @MainActor [weak self] in
            guard let self, !self.hasReportedCode else {
                return
            }

            self.hasReportedCode = true
            self.captureSession.stopRunning()
            self.onCodeScanned(value)
        }
    }

    private func configureCamera() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureCaptureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    if granted {
                        self.configureCaptureSession()
                    } else {
                        self.onError("Camera access was denied.")
                    }
                }
            }
        case .denied, .restricted:
            onError("Camera access is unavailable for QR scanning.")
        @unknown default:
            onError("Camera access is unavailable for QR scanning.")
        }
    }

    private func configureCaptureSession() {
        guard let device = AVCaptureDevice.default(for: .video) else {
            onError("No camera is available on this device.")
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: device)
            guard captureSession.canAddInput(input) else {
                onError("Unable to add the camera input.")
                return
            }
            captureSession.addInput(input)

            let metadataOutput = AVCaptureMetadataOutput()
            guard captureSession.canAddOutput(metadataOutput) else {
                onError("Unable to add QR metadata output.")
                return
            }
            captureSession.addOutput(metadataOutput)
            metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
            metadataOutput.metadataObjectTypes = [.qr]

            let previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
            previewLayer.videoGravity = .resizeAspectFill
            previewLayer.frame = view.layer.bounds
            view.layer.addSublayer(previewLayer)
            self.previewLayer = previewLayer

            captureSession.startRunning()
            hasStartedSession = true
        } catch {
            onError(error.localizedDescription)
        }
    }
}
#endif
