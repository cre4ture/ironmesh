import AppleCore
import SwiftUI
import UIKit

struct IronmeshGalleryView: View {
    @EnvironmentObject private var browserModel: IronmeshBrowserModel
    @StateObject private var galleryModel = IronmeshGalleryModel()
    @State private var mode: AppleGalleryMode = .allImages
    @State private var sort: AppleGallerySort = .newest
    @State private var selection: IronmeshGallerySelection?

    private var loadID: IronmeshGalleryLoadID {
        IronmeshGalleryLoadID(
            mode: mode,
            sort: sort,
            currentPath: mode == .currentFolder ? browserModel.currentPath : "",
            configuration: browserModel.draft.connectionConfiguration
        )
    }

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                controls

                if mode == .currentFolder {
                    currentFolderSummary
                }

                galleryContent
            }
            .padding(16)
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .task(id: loadID) {
            galleryModel.reload(
                mode: mode,
                sort: sort,
                currentPath: browserModel.currentPath,
                configuration: browserModel.draft.connectionConfiguration
            )
        }
        .onChange(of: loadID) { _ in
            selection = nil
        }
        .fullScreenCover(item: $selection) { selection in
            if let configuration = browserModel.draft.connectionConfiguration {
                IronmeshGalleryViewer(
                    galleryModel: galleryModel,
                    configuration: configuration,
                    initialPath: selection.path
                )
            }
        }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Photos")
                        .font(.headline)
                    Text("\(galleryModel.entries.count) of \(galleryModel.totalCount) loaded")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    galleryModel.refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }

            Picker("Scope", selection: $mode) {
                Text("All Images").tag(AppleGalleryMode.allImages)
                Text("Current Folder").tag(AppleGalleryMode.currentFolder)
            }
            .pickerStyle(.segmented)

            Picker("Sort", selection: $sort) {
                Text("Newest").tag(AppleGallerySort.newest)
                Text("Name").tag(AppleGallerySort.path)
            }
            .pickerStyle(.segmented)
        }
        .padding(14)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var currentFolderSummary: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text("Current Folder")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(displayPath(browserModel.currentPath))
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
            }
            Spacer()
        }
        .padding(14)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    @ViewBuilder
    private var galleryContent: some View {
        if galleryModel.entries.isEmpty, galleryModel.isLoading {
            VStack(spacing: 12) {
                ProgressView()
                Text("Loading image index…")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 48)
        } else if galleryModel.entries.isEmpty, let error = galleryModel.errorMessage {
            IronmeshGalleryMessageView(
                systemImage: "exclamationmark.triangle",
                title: "Photos could not be loaded",
                message: error,
                actionTitle: "Retry",
                action: galleryModel.retry
            )
        } else if galleryModel.entries.isEmpty {
            IronmeshGalleryMessageView(
                systemImage: "photo.on.rectangle.angled",
                title: "No images found",
                message: mode == .allImages
                    ? "The media index does not contain images yet."
                    : "No indexed images are available under \(displayPath(browserModel.currentPath))."
            )
        } else if let configuration = browserModel.draft.connectionConfiguration {
            if let error = galleryModel.errorMessage {
                IronmeshGalleryMessageView(
                    systemImage: "wifi.exclamationmark",
                    title: "The next page failed",
                    message: error,
                    actionTitle: "Retry page",
                    action: galleryModel.retry
                )
            }

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 112, maximum: 180), spacing: 8)],
                spacing: 8
            ) {
                ForEach(Array(galleryModel.entries.enumerated()), id: \.element.path) { index, entry in
                    IronmeshGalleryThumbnailCell(
                        entry: entry,
                        configuration: configuration,
                        repository: galleryModel.imageRepository,
                        onOpen: {
                            selection = IronmeshGallerySelection(path: entry.path)
                        }
                    )
                    .onAppear {
                        if index >= galleryModel.entries.count - 6 {
                            galleryModel.loadNextPage()
                        }
                    }
                }
            }

            if galleryModel.isLoading {
                ProgressView("Loading next page…")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            } else if galleryModel.canLoadMore {
                Button("Load more") {
                    galleryModel.loadNextPage()
                }
                .buttonStyle(.bordered)
            }
        }
    }
}

private struct IronmeshGalleryLoadID: Equatable {
    let mode: AppleGalleryMode
    let sort: AppleGallerySort
    let currentPath: String
    let configuration: AppleConnectionConfiguration?
}

private struct IronmeshGallerySelection: Identifiable {
    let path: String
    var id: String { path }
}

private struct IronmeshGalleryThumbnailCell: View {
    let entry: AppleStoreIndexEntry
    let configuration: AppleConnectionConfiguration
    let repository: IronmeshGalleryImageRepository
    let onOpen: () -> Void

    @State private var image: UIImage?
    @State private var errorMessage: String?
    @State private var retryGeneration = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color(uiColor: .secondarySystemGroupedBackground))

                if let image {
                    Button(action: onOpen) {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFill()
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                    .buttonStyle(.plain)
                } else if errorMessage != nil {
                    Button {
                        retryGeneration += 1
                    } label: {
                        VStack(spacing: 6) {
                            Image(systemName: "arrow.clockwise")
                            Text("Retry")
                                .font(.caption)
                        }
                    }
                    .buttonStyle(.bordered)
                } else {
                    ProgressView()
                }
            }
            .aspectRatio(1, contentMode: .fit)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))

            Text(galleryDisplayName(entry.path))
                .font(.caption)
                .lineLimit(1)

            if let takenAtUnix = entry.media?.takenAtUnix {
                Text(Date(timeIntervalSince1970: TimeInterval(takenAtUnix)), style: .date)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .task(id: "\(entry.path)-\(retryGeneration)") {
            image = nil
            errorMessage = nil
            do {
                let data = try await repository.thumbnailData(for: entry, configuration: configuration)
                try Task.checkCancellation()
                guard let decoded = UIImage(data: data) else {
                    throw IronmeshGalleryImageError.invalidImageData
                }
                image = decoded
            } catch is CancellationError {
                return
            } catch {
                errorMessage = error.localizedDescription
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(galleryDisplayName(entry.path))
    }
}

private struct IronmeshGalleryMessageView: View {
    let systemImage: String
    let title: String
    let message: String
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(24)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

private struct IronmeshGalleryViewer: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var galleryModel: IronmeshGalleryModel

    let configuration: AppleConnectionConfiguration
    @State private var selectedPath: String

    init(
        galleryModel: IronmeshGalleryModel,
        configuration: AppleConnectionConfiguration,
        initialPath: String
    ) {
        self.galleryModel = galleryModel
        self.configuration = configuration
        _selectedPath = State(initialValue: initialPath)
    }

    var body: some View {
        NavigationStack {
            TabView(selection: $selectedPath) {
                ForEach(Array(galleryModel.entries.enumerated()), id: \.element.path) { index, entry in
                    IronmeshGalleryFullImagePage(
                        entry: entry,
                        configuration: configuration,
                        repository: galleryModel.imageRepository
                    )
                    .tag(entry.path)
                    .onAppear {
                        if index >= galleryModel.entries.count - 4 {
                            galleryModel.loadNextPage()
                        }
                    }
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .automatic))
            .background(Color.black.ignoresSafeArea())
            .navigationTitle(galleryDisplayName(selectedPath))
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbarBackground(Color.black.opacity(0.85), for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}

private func galleryDisplayName(_ path: String) -> String {
    path.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? path
}

private struct IronmeshGalleryFullImagePage: View {
    let entry: AppleStoreIndexEntry
    let configuration: AppleConnectionConfiguration
    let repository: IronmeshGalleryImageRepository

    @State private var image: UIImage?
    @State private var errorMessage: String?
    @State private var retryGeneration = 0

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if let image {
                IronmeshZoomableImageView(image: image)
                    .ignoresSafeArea(edges: .bottom)
            } else if let errorMessage {
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.largeTitle)
                    Text(errorMessage)
                        .font(.footnote)
                        .multilineTextAlignment(.center)
                    Button("Retry") {
                        retryGeneration += 1
                    }
                    .buttonStyle(.borderedProminent)
                }
                .foregroundStyle(.white)
                .padding(24)
            } else {
                ProgressView("Loading full image…")
                    .tint(.white)
                    .foregroundStyle(.white)
            }
        }
        .task(id: "\(entry.path)-\(retryGeneration)") {
            image = nil
            errorMessage = nil
            do {
                let data = try await repository.fullImageData(for: entry, configuration: configuration)
                try Task.checkCancellation()
                guard let decoded = UIImage(data: data) else {
                    throw IronmeshGalleryImageError.invalidImageData
                }
                image = decoded
            } catch is CancellationError {
                return
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private enum IronmeshGalleryImageError: LocalizedError {
    case invalidImageData

    var errorDescription: String? {
        "The server returned image data that iOS could not decode."
    }
}

private struct IronmeshZoomableImageView: UIViewRepresentable {
    let image: UIImage

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> UIScrollView {
        let scrollView = UIScrollView()
        scrollView.backgroundColor = .black
        scrollView.minimumZoomScale = 1
        scrollView.maximumZoomScale = 6
        scrollView.bouncesZoom = true
        scrollView.showsHorizontalScrollIndicator = false
        scrollView.showsVerticalScrollIndicator = false
        scrollView.delegate = context.coordinator

        context.coordinator.imageView.contentMode = .scaleAspectFit
        context.coordinator.imageView.clipsToBounds = true
        scrollView.addSubview(context.coordinator.imageView)
        return scrollView
    }

    func updateUIView(_ scrollView: UIScrollView, context: Context) {
        let imageChanged = context.coordinator.imageView.image !== image
        context.coordinator.imageView.image = image
        context.coordinator.imageView.frame = scrollView.bounds
        scrollView.contentSize = scrollView.bounds.size
        if imageChanged {
            scrollView.setZoomScale(1, animated: false)
        }
    }

    final class Coordinator: NSObject, UIScrollViewDelegate {
        let imageView = UIImageView()

        func viewForZooming(in scrollView: UIScrollView) -> UIView? {
            imageView
        }

        func scrollViewDidZoom(_ scrollView: UIScrollView) {
            let horizontalInset = max(0, (scrollView.bounds.width - scrollView.contentSize.width) / 2)
            let verticalInset = max(0, (scrollView.bounds.height - scrollView.contentSize.height) / 2)
            scrollView.contentInset = UIEdgeInsets(
                top: verticalInset,
                left: horizontalInset,
                bottom: verticalInset,
                right: horizontalInset
            )
        }
    }
}
