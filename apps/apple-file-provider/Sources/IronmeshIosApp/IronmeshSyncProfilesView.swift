import AppleCore
import SwiftUI
import UIKit

struct IronmeshFilesView: View {
    @EnvironmentObject private var model: IronmeshBrowserModel
    @State private var showsFilesPicker = false
    @State private var showsNewProfile = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    IronmeshHeroCard(
                        title: model.syncProfiles.isEmpty
                            ? "Create a Files sync profile"
                            : "\(model.syncProfiles.count) Files sync profile(s)",
                        body: "Each profile maps one remote prefix into its own system-managed Files domain.",
                        tone: model.syncProfilesErrorMessage == nil ? .good : .warning
                    ) {
                        HStack {
                            Button("Add profile") { showsNewProfile = true }
                                .buttonStyle(.borderedProminent)
                                .disabled(model.isSyncProfileMutationInProgress)
                            Button("Refresh status") { model.refreshSyncProfileDomains() }
                                .buttonStyle(.bordered)
                            Button("Open Files") { showsFilesPicker = true }
                                .buttonStyle(.bordered)
                        }
                    }

                    if let error = model.syncProfilesErrorMessage {
                        IronmeshCard(title: "Sync profiles need attention") {
                            Text(error).font(.footnote).foregroundStyle(.red)
                        }
                    }

                    if model.syncProfiles.isEmpty {
                        IronmeshCard(
                            title: "No profiles yet",
                            subtitle: "Add separate domains for Documents, Photos, or any remote prefix."
                        ) {
                            Button("Create first profile") { showsNewProfile = true }
                                .buttonStyle(.borderedProminent)
                                .disabled(model.isSyncProfileMutationInProgress)
                        }
                    } else {
                        ForEach(model.syncProfiles) { profile in
                            IronmeshSyncProfileCard(profile: profile)
                        }
                    }

                    IronmeshCard(title: "Native Files lifecycle", subtitle: "No foreground timer or WorkManager port is used.") {
                        Text(model.filesIntegrationNote).font(.footnote).foregroundStyle(.secondary)
                    }

                    connectionDiagnostics

                    if !model.items.isEmpty {
                        IronmeshCard(title: "Root snapshot", subtitle: "Latest items visible at the top of the remote tree.") {
                            ForEach(model.items.prefix(5), id: \.identifier.serialized) { item in
                                IronmeshBrowserRow(item: item)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Sync")
        }
        .sheet(isPresented: $showsFilesPicker) {
            IronmeshFilesHandoffPicker { url in model.noteFilesSelection(url) }
        }
        .sheet(isPresented: $showsNewProfile) {
            IronmeshNewSyncProfileSheet()
        }
    }

    private var connectionDiagnostics: some View {
        IronmeshCard(title: "Connection diagnostics", subtitle: "App-side visibility into the current route.") {
            IronmeshKeyValueRow(label: "Connection role", value: model.connectionDiagnostics?.connectionName ?? "ios app shell")
            IronmeshKeyValueRow(label: "Status", value: model.statusText)
            IronmeshKeyValueRow(label: "Connection target", value: model.draft.normalizedConnectionInput ?? "Not configured")
            IronmeshKeyValueRow(label: "Last route success", value: syncUnixMillisecondsTimestamp(model.connectionDiagnostics?.lastSuccessUnixMs))
            IronmeshKeyValueRow(label: "Last library success", value: syncTimestamp(model.lastSuccessfulConnectionAt))
            IronmeshKeyValueRow(label: "Last root refresh", value: syncTimestamp(model.lastLibraryRefreshAt))
            if let lastErrorMessage = model.lastErrorMessage {
                IronmeshKeyValueRow(label: "Last error", value: lastErrorMessage)
            }
            HStack {
                Button("Refresh diagnostics") { model.refreshConnectionDiagnostics() }
                    .buttonStyle(.borderedProminent)
                Button("Open Web UI") { model.openWebUI() }
                    .buttonStyle(.bordered)
            }
            NavigationLink {
                IronmeshConnectionPathsView()
            } label: {
                Label("Inspect connection paths", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .buttonStyle(.bordered)
            .frame(maxWidth: .infinity, alignment: .leading)

            if model.orderedConnectionEndpoints.isEmpty {
                Text("No route attempts recorded yet.").foregroundStyle(.secondary)
            } else {
                ForEach(Array(model.orderedConnectionEndpoints.prefix(3))) { endpoint in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(endpoint.locator).font(.headline)
                            Spacer()
                            Text(endpoint.active ? "Active" : "Standby")
                                .font(.caption)
                                .foregroundStyle(endpoint.active ? .green : .secondary)
                        }
                        IronmeshKeyValueRow(label: "Path", value: endpoint.pathKind)
                        IronmeshKeyValueRow(label: "Base URL", value: endpoint.requestBaseUrl)
                        IronmeshKeyValueRow(label: "Failures", value: "\(endpoint.consecutiveFailures) consecutive, \(endpoint.totalFailures) total")
                        IronmeshKeyValueRow(label: "Successes", value: "\(endpoint.totalSuccesses)")
                        if let lastError = endpoint.lastError {
                            IronmeshKeyValueRow(label: "Last error", value: lastError)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if !model.recentConnectionAttempts.isEmpty {
                Divider()
                ForEach(Array(model.recentConnectionAttempts.prefix(4))) { attempt in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(attempt.method) \(attempt.outcome)").font(.headline)
                        Text(attempt.url).font(.footnote).foregroundStyle(.secondary)
                        Text(syncUnixMillisecondsTimestamp(attempt.startedUnixMs))
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.tertiary)
                        if let error = attempt.error {
                            Text(error).font(.caption).foregroundStyle(.red)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 2)
                }
            }
        }
    }
}

private struct IronmeshSyncProfileCard: View {
    @EnvironmentObject private var model: IronmeshBrowserModel
    let profile: AppleSyncProfile

    var body: some View {
        let registeredDomain = model.registeredDomain(for: profile)
        IronmeshCard(
            title: profile.displayName,
            subtitle: profile.lifecycle == .paused ? "Paused" : "Active"
        ) {
            IronmeshKeyValueRow(label: "Remote scope", value: profile.scopeSummary)
            IronmeshKeyValueRow(label: "Files domain", value: profile.domainIdentifier)
            IronmeshKeyValueRow(label: "Connection", value: "Shared enrolled device")
            IronmeshKeyValueRow(label: "Domain state", value: domainStateLabel(registeredDomain))
            IronmeshKeyValueRow(label: "Network", value: profileNetworkSummary(profile))
            IronmeshKeyValueRow(
                label: "Offline files",
                value: "System managed; use Keep Downloaded in Files"
            )
            HStack {
                if profile.lifecycle == .active {
                    Button("Pause") { model.pauseSyncProfile(profile) }.buttonStyle(.bordered)
                    Button("Discover changes") { model.requestSyncProfileRefresh(profile) }.buttonStyle(.bordered)
                } else {
                    Button("Resume") { model.resumeSyncProfile(profile) }.buttonStyle(.borderedProminent)
                }
                Button("Remove", role: .destructive) { model.removeSyncProfile(profile) }.buttonStyle(.bordered)
            }
            .disabled(model.isSyncProfileMutationInProgress)
        }
    }

    private func domainStateLabel(_ domain: AppleRegisteredFileProviderDomain?) -> String {
        guard let domain else { return "Not registered" }
        return domain.isDisconnected ? "Disconnected" : "Registered"
    }

    private func profileNetworkSummary(_ profile: AppleSyncProfile) -> String {
        [
            profile.networkPolicy.allowsExpensiveNetwork ? "expensive paths allowed" : "expensive paths blocked",
            profile.networkPolicy.allowsConstrainedNetwork ? "Low Data Mode allowed" : "Low Data Mode deferred",
            profile.powerPolicy.defersInLowPowerMode ? "Low Power Mode deferred" : "Low Power Mode allowed",
        ].joined(separator: ", ")
    }
}

private struct IronmeshNewSyncProfileSheet: View {
    @EnvironmentObject private var model: IronmeshBrowserModel
    @Environment(\.dismiss) private var dismiss
    @State private var displayName = ""
    @State private var remotePrefix = ""
    @State private var depth = 64
    @State private var allowsExpensiveNetwork = false
    @State private var allowsConstrainedNetwork = false
    @State private var defersInLowPowerMode = true

    var body: some View {
        NavigationStack {
            Form {
                Section("Remote scope") {
                    TextField("Profile name", text: $displayName)
                    TextField("Remote prefix (optional)", text: $remotePrefix)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Stepper("Discovery depth: \(depth)", value: $depth, in: 1...256)
                }
                Section("Network and power") {
                    Toggle("Allow expensive or cellular paths", isOn: $allowsExpensiveNetwork)
                    Toggle("Allow constrained Low Data Mode", isOn: $allowsConstrainedNetwork)
                    Toggle("Defer in Low Power Mode", isOn: $defersInLowPowerMode)
                }
                Section("Offline content") {
                    Text("iOS downloads files on demand. Pin individual files or folders with Keep Downloaded in Files; File Provider has no profile-level eager-retention API on iOS.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section("Connection") {
                    Text("Profiles intentionally reuse this device's enrolled connection and Keychain identity, matching Android's global device-auth model.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("New sync profile")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        let started = model.configureSyncProfile(
                            displayName: displayName,
                            remotePrefix: remotePrefix,
                            depth: depth,
                            allowsExpensiveNetwork: allowsExpensiveNetwork,
                            allowsConstrainedNetwork: allowsConstrainedNetwork,
                            defersInLowPowerMode: defersInLowPowerMode
                        )
                        if started {
                            dismiss()
                        }
                    }
                    .disabled(
                        displayName.nilIfBlank == nil
                            || model.isSyncProfileMutationInProgress
                    )
                }
            }
        }
    }
}

private func syncTimestamp(_ date: Date?) -> String {
    guard let date else { return "Unavailable" }
    return DateFormatter.localizedString(from: date, dateStyle: .medium, timeStyle: .medium)
}

private func syncUnixMillisecondsTimestamp(_ timestamp: UInt64?) -> String {
    guard let timestamp else { return "Unavailable" }
    return syncTimestamp(Date(timeIntervalSince1970: TimeInterval(timestamp) / 1_000))
}
