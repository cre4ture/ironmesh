# Android App UI Redesign Proposal

## Status

Proposal for redesigning the native Android client app in `apps/android-app`.

This note is based on the current implementation in:

- `apps/android-app/app/src/main/java/io/ironmesh/android/MainActivity.kt`
- `apps/android-app/app/src/main/java/io/ironmesh/android/ui/MainViewModel.kt`
- `apps/android-app/app/src/main/res/values/themes.xml`

The smaller `apps/android-server-node-app` already feels more focused, but it should share the
same visual system once the client app is redesigned.

## Goal

Move the Android app from an MVP control shell to a product-grade mobile client that:

- feels intentional and trustworthy,
- surfaces the sync state immediately,
- separates onboarding, daily use, and advanced tools,
- keeps technical power features available without making them the default experience,
- aligns with the existing Ironmesh brand direction already visible in the web theme and logo.

## Current Assessment

The current app works, but the UI model is still shaped like a developer console.

Main issues:

- The root screen is one large vertical surface with a logo row, section chips, a global status
  card, and then a large block of mixed controls.
- `Settings` currently combines onboarding, device identity, manual storage tests, file browsing,
  folder-sync setup, permissions, runtime status, and history in one place.
- `Web UI` is treated like a top-level destination even though it is mainly a launcher into another
  surface.
- The status model is too global. Loading, errors, success messages, and raw response content all
  compete in one panel.
- The gallery has the clearest interaction model in the app, but some important controls are hidden
  behind gestures instead of being clearly exposed.
- Permission requests are functional but not guided. The app often asks at the moment of need
  rather than explaining why the permission matters beforehand.
- The visual layer is almost pure Material defaults. There is no strong brand expression, no token
  system, and almost all strings are inline.
- Most of the UI lives in one large file, which makes it harder to refine behavior screen by
  screen.

## Product Direction

The app should present itself as a mobile control surface for one clear job:

- connect this phone to an Ironmesh deployment,
- keep one or more folders in sync,
- inspect recent work and media,
- hand off to the richer web surface only when needed.

That implies a different information architecture.

## Target Navigation Model

Use a `Scaffold` with a persistent bottom navigation bar on phones and a navigation rail on wide
layouts.

Primary destinations:

- `Home`
- `Sync`
- `Library`
- `Settings`

Rules:

- `Web UI` stops being a main tab.
- `Open Web Console` becomes a secondary action from `Home` and `Settings`.
- Developer-only actions such as raw `PUT`/`GET` tests move into a clearly labeled `Advanced`
  section under `Settings`.
- Enrollment is not mixed into the main shell when the device is not set up yet. It becomes a
  dedicated onboarding flow.

## Visual Direction

The current brand already suggests a better visual language than the app uses today.

Reference points already present in the repo:

- Web theme uses `teal` as the primary color.
- Web theme uses `Space Grotesk`.
- The logo and mark use a steel and teal palette with layered depth.

Recommended visual system:

- Background: soft neutral surface, not flat pure white.
- Primary accents: deep teal, bright mint-teal, dark steel.
- Cards: layered surfaces with clear elevation differences between summary cards and editable forms.
- Corners: consistent large radius, around `20dp` to `24dp` for major cards and sheets.
- Typography:
  - `Space Grotesk` for headings and section titles,
  - system sans for dense body copy if better for Android readability,
  - tabular numerals for metrics and timestamps where useful.
- Iconography: simple geometric line icons that match the mesh brand rather than generic playful
  icons.
- Status colors:
  - success: deep teal/green,
  - warning: amber,
  - error: rust red,
  - neutral runtime state: slate.

Tone:

- precise,
- calm,
- technical but not raw,
- polished without looking consumer-social.

## Screen Concept

### 1. Onboarding

Show this instead of the main app when no valid device enrollment exists.

Steps:

1. Welcome and short explanation of what Ironmesh does on Android.
2. Import bootstrap claim:
   - paste,
   - scan QR,
   - optionally open help.
3. Name this device.
4. Confirm required access:
   - folder access,
   - photo metadata access only if gallery/photo sync needs it,
   - Wi-Fi access only if restricted network rules are configured.
5. Completion screen with next actions:
   - `Create sync`,
   - `Open library`,
   - `Open web console`.

Wireframe:

```text
+--------------------------------------------------+
| Ironmesh                                         |
| Connect this phone to your edge storage          |
|                                                  |
| [ Paste claim ]   [ Scan QR ]                    |
|                                                  |
| Device name                                      |
| [ Uli Pixel 9 Pro                           ]    |
|                                                  |
| Why we need access                               |
| - folder access for sync                         |
| - photo metadata for originals                   |
| - Wi-Fi names only for restricted rules          |
|                                                  |
|                           [ Continue ]           |
+--------------------------------------------------+
```

Why:

- removes first-run cognitive overload,
- avoids showing empty tabs and technical controls before enrollment,
- gives permissions a reason and a sequence.

### 2. Home

This becomes the app's operational dashboard.

Contents:

- identity header with device name and connection status,
- hero status card with current sync engine state,
- quick metrics:
  - active profiles,
  - last successful sync,
  - recent uploads/downloads,
  - current network policy result,
- primary actions:
  - `Sync now`,
  - `Create sync`,
  - `Open library`,
  - `Open web console`,
- small event feed with the latest important activity or errors.

Wireframe:

```text
+--------------------------------------------------+
| Ironmesh                          Connected      |
| Pixel 9 Pro                                       |
|                                                  |
| Sync is healthy                                  |
| 3 profiles active                                |
| Last success 09:42                               |
| [ Sync now ]  [ Open web console ]               |
|                                                  |
| Today                                            |
| [Uploads 42] [Downloads 18] [Errors 0]           |
|                                                  |
| Recent activity                                  |
| Uploaded DCIM/IMG_1043.jpg                       |
| Downloaded docs/invoice.pdf                      |
|                                                  |
| Suggested next step                              |
| Create a second sync profile for Documents       |
+--------------------------------------------------+
```

Why:

- gives the user one answer immediately: "is Ironmesh working on this phone right now?"
- makes daily usage possible without entering settings,
- promotes the web console as an advanced action, not the primary product.

### 3. Sync

This is the operational core of the app.

Sections:

- top summary strip:
  - engine state,
  - active profiles,
  - blocked profiles,
  - last success,
- profile list,
- per-profile detail sheet,
- profile creation flow,
- activity timeline.

Each profile card should show:

- label,
- local folder,
- remote scope,
- enabled/paused state,
- network rule summary,
- last successful run,
- current phase or current issue,
- actions:
  - enable/disable,
  - edit,
  - run now,
  - remove.

Recommended interaction:

- tap profile card to open a bottom sheet,
- edit network rules in a modal bottom sheet instead of a raw dialog,
- show activity inline as a timeline with small semantic icons.

Wireframe:

```text
+--------------------------------------------------+
| Sync                                             |
| Healthy     3 active     1 blocked               |
|                                                  |
| + New profile                                    |
|                                                  |
| Camera Roll                                      |
| /storage/emulated/0/DCIM                         |
| -> photos/phone/                                 |
| Wi-Fi only | last success 09:42                  |
| [Enabled] [Run now] [Edit]                       |
|                                                  |
| Documents                                        |
| /storage/emulated/0/Documents                    |
| -> docs/mobile/                                  |
| Blocked by network rule                          |
| [Paused] [Fix] [Edit]                            |
|                                                  |
| Recent activity                                  |
| 09:42 Upload IMG_1043.jpg                        |
| 09:40 Download invoice.pdf                       |
| 09:37 Error Wi-Fi name unavailable               |
+--------------------------------------------------+
```

Why:

- folder sync is the app's real native value,
- the current UI exposes the raw configuration, but not a clean operational model,
- profiles should feel like managed assets, not form rows.

### 4. Library

The gallery already contains useful logic and should be upgraded into a first-class media browser.

Recommended changes:

- replace gesture-only density changes with a visible segmented control:
  - `Comfortable`,
  - `Compact`,
  - `Dense`.
- keep pinch-to-resize as a secondary shortcut, not the only discovery path.
- move sort and scope controls into a toolbar row or sheet.
- use sticky breadcrumbs in folder mode.
- make thumbnails visually cleaner with consistent placeholders and subtle metadata overlays.
- fullscreen viewer gets a proper immersive top app bar with:
  - close,
  - filename,
  - share/export later if needed.

Wireframe:

```text
+--------------------------------------------------+
| Library                          [Refresh]       |
| [All images] [Current folder] [Newest]           |
| [Comfortable] [Compact] [Dense]                  |
|                                                  |
| /  DCIM  Camera                                  |
|                                                  |
| [img] [img] [img]                                |
| [img] [img] [img]                                |
| [img] [img] [img]                                |
+--------------------------------------------------+
```

Why:

- turns the gallery into an understandable navigation surface,
- reduces hidden behavior,
- makes the app feel like a product instead of a demo.

### 5. Settings

`Settings` should be smaller and quieter than it is today.

Suggested groups:

- `Device`
  - enrolled identity,
  - rename device,
  - clear enrollment.
- `Permissions`
  - folder access status,
  - photo metadata access status,
  - Wi-Fi rule access status,
  - guided repair buttons.
- `Storage & Files`
  - open Ironmesh root in Files,
  - storage diagnostics.
- `Advanced`
  - open web console,
  - developer tests,
  - version/build info,
  - logs/export later.

Rules:

- no large operational content lives here,
- avoid showing sync history or sync runtime detail in settings,
- keep it mainly for repair, maintenance, and advanced tasks.

## Interaction Rules

These rules matter more than colors.

### Status feedback

Replace the current global status block with three layers:

- inline field validation near the source of the problem,
- transient snackbar for short success/failure messages,
- persistent banners or cards for ongoing states such as:
  - sync blocked,
  - missing enrollment,
  - missing required permission.

### Permissions

Never request sensitive permissions without a short explainer step.

Pattern:

- user taps a feature,
- app shows why the permission is needed,
- user confirms,
- system permission request opens,
- result returns into a clear success or repair state.

### Empty states

Every empty state should include one next action.

Examples:

- no sync profiles: `Create your first sync`
- no gallery items: `Open a synced folder` or `Run sync now`
- no enrollment: `Connect this phone`

### Error handling

Errors should be classified and phrased for humans.

Preferred buckets:

- `Connection issue`
- `Permission needed`
- `Network rule blocked`
- `Sync conflict`
- `Unknown error`

Do not expose raw backend language as the primary copy unless the user opens an advanced details
expander.

## Component Model

The redesign should also clean up the Compose structure.

Recommended package split:

- `ui/theme`
- `ui/navigation`
- `ui/components`
- `ui/screens/onboarding`
- `ui/screens/home`
- `ui/screens/sync`
- `ui/screens/library`
- `ui/screens/settings`
- `ui/state`

Recommended shared components:

- `IronmeshAppShell`
- `StatusHeroCard`
- `MetricPill`
- `ProfileCard`
- `ActivityTimeline`
- `PermissionExplainerCard`
- `EmptyStateCard`
- `SectionHeader`
- `IronmeshTopBar`

This should replace the current pattern where most of the surface composition sits in
`MainActivity.kt`.

## Theme and Token Plan

The app should stop relying on raw Material defaults.

Create a dedicated Android theme layer with:

- color roles derived from the logo and web theme,
- typography scale with `Space Grotesk` headings,
- spacing tokens,
- corner radius tokens,
- card style variants,
- state chips and badge styles,
- light and dark variants tuned by design rather than accepted as defaults.

Suggested palette direction:

- `Ink`: `#112523`
- `Deep Teal`: `#0D6B5C`
- `Teal`: `#14B8A6`
- `Mint`: `#74E4C8`
- `Mist`: very light cool neutral for backgrounds
- `Rust Error`: muted red, less saturated than stock Material error

## Implementation Approach

This redesign should not start with a full logic rewrite.

Recommended sequence:

### Phase 1. Foundation

- Introduce the theme/token layer.
- Move strings into resources.
- Replace the chip-based root navigation with `Scaffold` plus bottom navigation.
- Split the main file into screen modules without changing app behavior yet.

### Phase 2. Onboarding and Home

- Build the first-run onboarding flow.
- Add the new `Home` dashboard.
- Route unenrolled users into onboarding by default.

### Phase 3. Sync Center

- Rebuild folder sync UI as a profile-based screen.
- Convert network-rule editing to bottom sheets.
- Replace history rows with a timeline component.

### Phase 4. Library

- Rebuild gallery controls into a visible toolbar model.
- Improve empty/loading/error states.
- Polish fullscreen viewer chrome and transitions.

### Phase 5. Settings and Advanced Tools

- Move developer features and maintenance actions into `Settings > Advanced`.
- Add repair-oriented permission panels.
- Keep the web console launch here as a secondary path.

### Phase 6. Shared Android Visual System

- Apply the same token set to `apps/android-server-node-app`.
- Keep separate app flows, but unify branding and component quality.

## Delivery Backlog

Concrete backlog items:

- Create `IronmeshTheme` for Android.
- Add branded typography and font loading.
- Introduce `IronmeshAppShell` with bottom navigation.
- Create destination-specific screen composables and route state.
- Replace global status text with snackbar plus banners.
- Add onboarding screen flow and enrollment gating.
- Build `Home` dashboard cards from current sync/runtime data.
- Build reusable sync profile cards and edit sheets.
- Convert gallery controls from hidden gestures to visible controls.
- Move all hard-coded strings into `strings.xml`.
- Add screenshot coverage for the main screens.
- Add Compose UI tests for:
  - onboarding gating,
  - navigation,
  - permission explainer display,
  - sync profile editing,
  - gallery toolbar behavior.

## Success Criteria

The redesign is successful when:

- a first-time user can understand the app structure without prior explanation,
- the current sync state is visible within two seconds after launch,
- daily use does not require entering a catch-all settings screen,
- advanced features remain available but no longer dominate the experience,
- the app looks recognizably like Ironmesh rather than default Compose scaffolding.

## Recommendation

Do not polish the current shell incrementally.

The better path is:

1. keep the existing business logic and repository layer,
2. rebuild the native app shell around a new navigation and theme foundation,
3. treat onboarding, home, sync, library, and settings as separate product surfaces,
4. demote the current web console handoff from a primary tab to an advanced secondary action.
