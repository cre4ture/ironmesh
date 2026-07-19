# Server-Node Hardware & Reliability Telemetry Strategy

Status: Concept / not yet implemented

Related documents:

- `docs/server-node-hardware-health-strategy.md` — per-node hardware inventory, SMART enrichment,
  and structured findings (`hardware_health_report`), already implemented
  (`crates/server-node-sdk/src/hardware_health.rs`).
- `docs/server-node-storage-stats-strategy.md` — per-node storage accounting, incremental counters,
  periodic reconciliation, and history retention conventions.
- `docs/security-architecture.md` — trust boundaries, mTLS node identity, admin plane model.
- `docs/multi-node-strategy.md` — cluster metadata model and the only existing "many nodes talk to
  one central service" precedent (rendezvous).
- `docs/data-scrub-auto-repair-strategy.md` — existing IronMesh-runtime-derived reliability findings.
- `docs/node-memory-footprint-reduction-plan.md` — precedent for resource-conscious background work.
- `docs/zero-touch-cluster-setup-strategy.md` — precedent for guided, low-friction admin UX.

## 1. Motivation / Kontext

`docs/server-node-hardware-health-strategy.md` hat bereits einen soliden, node-lokalen Baustein
geschaffen: jeder Server-Node sammelt eine normalisierte Hardware-Inventur (System/Board/BIOS, CPU,
RAM, Storage inkl. optionalem `smartctl`-Enrichment, NICs), führt eine Lifecycle-Historie
(`node_first_seen_at_unix`, Component-Sichtungen, kumulierte Uptime) und leitet daraus strukturierte
`findings` sowie generierte `health_notes` ab. Das Ergebnis ist über einen admin-authentifizierten
Endpoint (`GET /api/v1/auth/hardware/health`) und eine dedizierte `HardwarePage` im `server-admin`
sichtbar — aber ausdrücklich **nur node-lokal**: "This slice does not implement a central fleet
collector. It deliberately stops at producing a safe, structured per-node report that a future
central service can ingest as-is."

Dieses Dokument beschreibt genau diesen nächsten Schritt: die **freiwillige (Opt-out, also
standardmäßig aktive) Übertragung** einer bereinigten, projektweit vergleichbaren Teilmenge dieser
Daten an einen zentralen Statistiksammelserver.

Nutzen für das Projekt:

- Fleet-weite Auswertung, welche Hardware-Modelle/Firmware-Kombinationen überdurchschnittlich oft
  SMART-Warnungen, Scrub-Fehler oder Ausfälle produzieren — over Zeit und über alle Installationen,
  nicht nur den einzelnen Cluster eines Betreibers.
- Frühwarnung für Nutzer und Projekt-Maintainer: "Modell X mit Firmware Y zeigt in der Flotte
  auffällig oft `media_errors`."
- Belastbarere Kapazitätsplanung/Empfehlungen ("welche NVMe-Klassen laufen in der Praxis wie lange").
- Datenbasis für zukünftige automatisierte Warnungen im Admin-UI ("dieses Modell hat fleet-weit eine
  erhöhte Ausfallquote").

Nutzen für den einzelnen Betreiber: im Gegenzug für die Teilnahme kann `server-admin` künftig
Fleet-Vergleichswerte anzeigen (z. B. "dein Node liegt bei Power-On-Hours im Fleet-Median"), was ohne
zentrale Sammlung nicht möglich ist.

Diese Funktion ist ausdrücklich von `docs/server-node-hardware-health-strategy.md` und
`docs/server-node-storage-stats-strategy.md` abzugrenzen: Beide bestehenden Dokumente/Implementierungen
bleiben node-lokal und "nicht anonym" (das Board erlaubt dort explizit `reporting_node_id` und exakte
Hardware-Details, da der Admin des eigenen Clusters ohnehin Zugriff hat). Sobald Daten den
Cluster-Vertrauensbereich verlassen und an einen von Dritten (den Projektbetreibern) kontrollierten
Dienst gehen, gelten strengere Datensparsamkeits- und Anonymisierungsregeln (siehe Abschnitt 4). Dieses
Dokument definiert daher einen **Export-/Reduktionsschritt**, keine 1:1-Weiterleitung des bestehenden
`hardware_health_report`.

## 2. Erfasste Metriken

Basis ist, wo möglich, das bereits implementierte Sammlungsmodell aus `hardware_health.rs`
(Linux-Zielplattform: sysfs/procfs, `sysinfo`, optional `smartctl --json`). Für jede Metrik:
Erfassbarkeit unter Linux, Aufwand, Nutzen.

### 2.1 Storage / SMART (bereits implementiert, wiederverwendbar)

| Metrik | Erfassbarkeit Linux | Aufwand | Nutzen |
| --- | --- | --- | --- |
| `reallocated_sector_count` | `smartctl --json`, bereits im Code (`HardwareStorageSmartInfo`) | keiner (reuse) | starker Frühindikator für HDD/SATA-SSD-Ausfall |
| `pending_sector_count` | dito | keiner | starker Frühindikator |
| `offline_uncorrectable_sector_count` | dito | keiner | starker Frühindikator |
| `crc_error_count` | dito | keiner | Kabel-/Interface-Probleme, kein reiner Medienfehler |
| `power_on_hours` | dito | keiner | Alters-/Abnutzungsvergleich pro Modell |
| `power_cycle_count` | dito | keiner | Belastungsprofil |
| `unsafe_shutdown_count` | dito | keiner | Korrelation mit Filesystem-/Metadaten-Fehlern |
| `percentage_used` / `available_spare_percent` | dito (NVMe) | keiner | NVMe-Lebensdauer |
| `media_errors` / `error_log_entries` | dito (NVMe) | keiner | direkte Fehlerindikatoren |
| `temperature_celsius` | dito | keiner | Betriebsbedingungen, Korrelation mit Ausfallraten |
| `smart_passed` (Gesamturteil) | dito | keiner | Kompakter Health-Status |
| `is_rotational`, `interface_type`, `bus_type` | bereits im Inventar | keiner | Segmentierung der Auswertung nach Laufwerkstyp |

Alle diese Felder existieren bereits 1:1 in `HardwareStorageSmartInfo` /
`HardwareStorageDevice` und müssen nur selektiert, nicht neu erfasst werden.

### 2.2 Node-Lifecycle / Uptime (bereits implementiert)

| Metrik | Erfassbarkeit | Aufwand | Nutzen |
| --- | --- | --- | --- |
| `uptime_seconds`, `cumulative_observed_uptime_seconds` | bereits erfasst (`HardwareNodeLifecycle`) | keiner | Zuverlässigkeits-/Crash-Häufigkeits-Proxy (viele kurze Uptimes = instabil) |
| `boot_id`-Wechselrate | ableitbar aus persistiertem State | gering | Reboot-/Crash-Frequenz pro Hardwareprofil |
| `hardware_profile_id` | bereits erfasst (deterministischer Hash über normalisiertes Inventar) | keiner | Gruppierungsschlüssel für Fleet-Vergleich, ohne Rohdaten preiszugeben |

### 2.3 IronMesh-Runtime-Zuverlässigkeit (teilweise implementiert)

| Metrik | Erfassbarkeit | Aufwand | Nutzen |
| --- | --- | --- | --- |
| Data-Scrub-Findings nach `finding_code` (siehe `docs/data-scrub-auto-repair-strategy.md`) | bereits vorhanden als Scrub-Historie | gering (Aggregation zu Zählern) | zeigt Storage-Instabilität, die SMART noch nicht meldet |
| Repair-Erfolg/-Fehlschlagsraten | bereits vorhanden als Repair-Historie | gering | Zuverlässigkeit des Selbstheilungspfads über die Flotte |
| Sampler-/Collector-Fehler (Storage-Stats-, Process-Stats-Sampler) | bereits im `hardware_health`-Collector-Status-Modell vorgesehen | keiner | erkennt Umgebungen, in denen Collector strukturell fehlschlagen (z. B. fehlendes `smartctl`) |

### 2.4 RAM/CPU-Fehler (nicht implementiert, Grenzen)

- **ECC-Fehler (RAM):** Unter Linux grundsätzlich über `EDAC` (`/sys/devices/system/edac/mc/mc*/ce_count`,
  `.../ue_count`) auslesbar — *aber nur*, wenn das Board/BIOS ECC-RAM und den EDAC-Treiber unterstützt.
  Auf der Mehrzahl der Consumer-Boards (kein ECC) liefert das nichts. Aufwand: gering (sysfs-Parsing,
  optionales Feld analog zu `smartctl`), Nutzen: mittel, aber nur für einen Teil der Flotte (Server-/
  Workstation-Boards) aussagekräftig. Empfehlung: als optionales Feld mit `available: bool` analog zu
  den bestehenden Collector-Status-Mustern aufnehmen, nicht blockierend für den ersten Schritt.
- **CPU-Fehler:** Es gibt keine verlässliche, breit verfügbare Linux-Schnittstelle für korrigierte
  CPU-interne Fehler auf Consumer-Hardware (MCE/`mcelog` existiert, ist aber uneinheitlich verfügbar
  und erfordert oft Root-Rechte über das Server-Prozess-Sandboxing hinaus). Statt echter CPU-Fehler
  zunächst nur **CPU-Throttling-Ereignisse** über `/sys/class/thermal` als Proxy für thermische
  Probleme erfassen (gering Aufwand, mittlerer Nutzen). Echtes MCE-Logging bleibt offene Frage
  (Abschnitt 8).

### 2.5 Netzwerk-Fehlerraten (nicht implementiert, geringer Zusatzaufwand)

- `rx_errors`, `tx_errors`, `rx_dropped`, `rx_crc_errors` je Interface sind unter Linux direkt über
  `/sys/class/net/<iface>/statistics/*` lesbar (kein Root, kein Zusatztool nötig). Aufwand: gering.
  Nutzen: mittel — vor allem als Korrelationssignal für Replikations-/Transport-Probleme, weniger als
  eigenständiger "Hardware-Reliability"-Indikator. Für die erste Ausbaustufe als optionale, niedrig
  priorisierte Ergänzung vorgesehen, nicht Teil des minimalen Kernschemas (Abschnitt 7).

### 2.6 Bewusst ausgeschlossen

Analog zur "Forbidden"-Liste in `docs/server-node-hardware-health-strategy.md`, aber für den
zentralen Sammelserver zusätzlich verschärft (siehe Abschnitt 4): keine `hostnames`, `IP-Adressen`,
`MAC-Adressen`, `object keys`/`paths`, rohe Seriennummern, rohe Log-Zeilen, `public_url`,
`cluster_id`, Nutzer-/Adminlabels.

## 3. Opt-out-Mechanik

### 3.1 Standardverhalten

Die Übertragung ist **standardmäßig aktiv** ("Opt-out", nicht "Opt-in"), analog zum bestehenden
Muster für andere Hintergrund-Features im Node (`IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED`,
`IRONMESH_REPLICATION_REPAIR_ENABLED`, `IRONMESH_STARTUP_REPAIR_ENABLED`,
`IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED` — alle in `crates/server-node-sdk/src/lib.rs` mit
`.unwrap_or(true)` und der gleichen `"0" | "false" | "no"`-Parsing-Konvention implementiert).

Vorschlag für die neue Umgebungsvariable, exakt im bestehenden Stil:

```rust
telemetry_enabled: std::env::var("IRONMESH_RELIABILITY_TELEMETRY_ENABLED")
    .ok()
    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
    .unwrap_or(true),
```

### 3.2 Abschaltwege

- **Env-Var / Config** (primär, konsistent mit allen bestehenden Feature-Togglen im Node):
  `IRONMESH_RELIABILITY_TELEMETRY_ENABLED=0`.
- **Admin-UI-Toggle** (für Betreiber, die nicht an der Konfigurationsdatei/Umgebung arbeiten
  wollen): ein Schalter in der bestehenden `HardwarePage` in `server-admin`
  (`web/apps/server-admin/src/pages/HardwarePage.tsx`) direkt neben der bestehenden
  Hardware-Health-Anzeige, da dort inhaltlich der engste Bezug besteht. Die Umschaltung müsste
  persistent im Node-State gespeichert werden (nicht nur env), damit sie einen Neustart übersteht —
  hierfür wird ein neuer, kleiner persistenter Zustandseintrag benötigt (analog zum Muster
  `health/hardware-health-state.json`), der die Env-Var als Default, aber die UI-Einstellung als
  Override behandelt.
- Admin-Endpoint zum Lesen/Setzen, nach dem bestehenden Auth-Muster (`authorize_admin_request`,
  wie in `hardware_health_current`): z. B. `GET/PUT /api/v1/auth/telemetry/settings`.

### 3.3 Transparenz vor dem Senden

Wichtig für Vertrauen und DSGVO-Transparenzpflicht: der Betreiber muss **vor** jeder Übertragung genau
sehen können, was gesendet würde. Analog zur bereits im Hardware-Health-Dokument formulierten
Anforderung ("The page should make export easy by exposing the exact JSON payload"):

- Neuer Preview-Endpoint `GET /api/v1/auth/telemetry/preview`, der exakt das JSON-Objekt liefert,
  das beim nächsten Batch tatsächlich gesendet würde (gleicher Serialisierungscode wie der echte
  Versand, kein separat gepflegtes "Beispielschema").
- Server-admin zeigt diesen Preview in der HardwarePage/Settings-Sektion an, inklusive eines
  Zeitstempels "zuletzt gesendet am ..." und eines Links/Buttons "letzten gesendeten Payload
  erneut anzeigen" (dafür wird der zuletzt gesendete Payload zusätzlich node-lokal aufbewahrt,
  z. B. die letzten N Batches, nicht nur der aktuelle Preview).
- Ein lokales Log-Ereignis (via bestehende `tracing`/`LogBuffer`-Infrastruktur, die bereits für den
  `server-admin` Logs-Tab existiert) bei jedem tatsächlichen Sendevorgang, sodass Betreiber es auch im
  Logs-Tab nachvollziehen können.

## 4. Datenschutz (DSGVO-relevant)

Die im Hardware-Health-Dokument bereits definierten Datensparsamkeitsregeln (keine Pfade, URLs, IPs,
Hostnames, MACs, rohen Seriennummern, rohen Logs) gelten hier unverändert als Untergrenze — sie
gelten für die Daten, die *überhaupt* aus dem `hardware_health_report` extrahiert werden dürfen.
Zusätzlich, weil die Daten jetzt einen fremdkontrollierten zentralen Dienst erreichen:

### 4.1 Pseudonymisierung statt Klartext-Node-Identität

Der bestehende `reporting_node_id` (stabile, im Cluster sichtbare Node-UUID) darf **nicht** direkt an
den zentralen Sammelserver übertragen werden, da er potenziell mit anderen cluster-internen
Informationen (z. B. durch den Betreiber selbst) re-identifizierbar ist und über Zeit ein stabiles
Tracking-Merkmal für Betreiber-Infrastruktur wäre.

Stattdessen: ein lokal abgeleiteter **Telemetrie-Pseudonym-Schlüssel**

```text
telemetry_subject_id = HMAC-SHA256(local_random_salt, "ironmesh-telemetry-v1" || node_id)
```

- `local_random_salt` wird beim ersten Opt-in-Zustand (bzw. beim ersten aktivierten Versand) einmalig
  lokal generiert und persistiert (z. B. in derselben State-Datei wie der Telemetrie-Toggle), nie
  übertragen.
- Damit ist `telemetry_subject_id` über die Zeit stabil genug für Longitudinal-Auswertung
  ("dieser Node zeigt seit 3 Wochen steigende `reallocated_sector_count`"), aber nicht auf den
  cluster-internen `node_id` rückführbar, ohne den lokalen Salt zu kennen.
- Rotation: analog zur 90-Tage-Retention-Konvention aus `docs/server-node-storage-stats-strategy.md`
  kann eine optionale periodische Rotation (z. B. alle 180 Tage) angeboten werden, um Langzeit-Tracking
  zusätzlich zu erschweren — das trennt aber bestehende Zeitreihen; das genaue Rotationsintervall ist
  eine offene Frage (Abschnitt 8) mit Zielkonflikt Statistik-Kontinuität vs. Datenschutz.
- **Keine** `cluster_id`, `public_url`, Node-Labels oder sonstige Cluster-Zuordnung wird mitgeschickt.

### 4.2 Keine Standortdaten

Es werden keinerlei Geo-/Standortinformationen erfasst oder übertragen (ohnehin nicht Teil des
bestehenden Hardware-Health-Modells). Auch grobe Ableitungen (Zeitzone, Spracheinstellung) sind
ausgeschlossen.

### 4.3 Aggregation zur Vermeidung von Rückschlüssen

- `hardware_profile_id` (bereits deterministisch aus normalisiertem Inventar gehasht, siehe
  Hardware-Health-Doku) bleibt der Gruppierungsschlüssel für Fleet-Vergleiche, nicht das exakte
  Rohinventar. Für seltene Hardwarekombinationen (z. B. ein einzigartiges Custom-Board) sollte der
  zentrale Dienst Gruppen unterhalb einer Mindestgröße (z. B. < 5 Nodes je `hardware_profile_id`)
  nicht in öffentlich/aggregiert zugänglichen Auswertungen einzeln ausweisen, um De-Anonymisierung
  durch Kombination seltener Merkmale zu verhindern (k-Anonymitäts-Schwelle).
- Rohdaten (pro-`telemetry_subject_id`-Batches) werden getrennt von aggregierten/veröffentlichten
  Statistiken gespeichert und sind nicht öffentlich einsehbar (siehe Abschnitt 5.3).

### 4.4 Rechtsgrundlage bei Opt-out-Modell

Ein "aktiv per Default, abschaltbar"-Modell ist datenschutzrechtlich anspruchsvoller als echtes
Opt-in, weil Art. 6 Abs. 1 DSGVO grundsätzlich eine Einwilligung (Opt-in) oder eine andere
Rechtsgrundlage verlangt — eine bloße Widerspruchsmöglichkeit ersetzt keine Einwilligung, wenn
personenbezogene Daten verarbeitet werden. Da Hardware-/Zuverlässigkeitsdaten von Server-Infrastruktur
in der Regel keine unmittelbaren Personendaten sind, aber ein pseudonymisierter, über Zeit
verfolgbarer Datensatz grundsätzlich als personenbezogen gelten *kann* (Re-Identifizierbarkeit über
Zusatzwissen des Betreibers), wird empfohlen:

- Rechtsgrundlage **berechtigtes Interesse** (Art. 6 Abs. 1 lit. f DSGVO) des Projekts an
  Zuverlässigkeitsstatistik, gestützt auf:
  - starke Datenminimierung (Abschnitt 4.1–4.3),
  - volle Transparenz vor jedem Versand (Abschnitt 3.3),
  - einfacher, jederzeit wirksamer Widerspruch (Opt-out),
  - keine Übertragung von Nutzerinhalten/Objektdaten.
- Diese Einschätzung ist **kein Ersatz für eine juristische Prüfung** vor Produktivbetrieb
  (siehe Abschnitt 8) — insbesondere bei Nutzern in der EU sollte vor dem Rollout eine
  Datenschutz-Folgenabschätzung bzw. zumindest eine Kurzprüfung erfolgen, da "Opt-out per Default"
  in Teilen der DSGVO-Auslegung kritisch gesehen wird (vgl. z. B. Cookie-Rechtsprechung, die für
  vergleichbare Fälle Opt-in verlangt). Eine denkbare Alternative wäre, den ersten Start nach Rollout
  dieser Funktion mit einer expliziten, aber vorausgewählten Bestätigung im Setup-/Bootstrap-Flow
  zu verbinden (Anknüpfungspunkt: `docs/zero-touch-cluster-setup-strategy.md`, Schritt "Start a new
  cluster" / "Join an existing cluster"), um Transparenz zu erhöhen, ohne ein echtes Opt-in-Muster
  im laufenden Betrieb zu erzwingen.

### 4.5 Lösch- und Auskunftsrechte

- Da `telemetry_subject_id` ohne den lokal gehaltenen Salt nicht auf einen Node rückführbar ist,
  kann der zentrale Dienst selbst keine Auskunfts-/Löschanfrage einem Betreiber zuordnen — der
  Betreiber muss dafür seinen eigenen `telemetry_subject_id`-Wert vorlegen (im Preview/Settings-UI
  sichtbar zu machen, siehe Abschnitt 3.3).
- Admin-UI erhält daher zusätzlich eine "Lösch-/Auskunftsanfrage stellen"-Aktion, die
  `telemetry_subject_id` anzeigt und einen vorbereiteten Kontaktweg/E-Mail-Text anbietet
  (Ausgestaltung offen, Abschnitt 8).
- Der zentrale Dienst muss auf Anfrage eines `telemetry_subject_id` alle zugehörigen Rohdatensätze
  löschen können, ohne aggregierte aber bereits k-anonymisierte Statistiken rückwirkend korrigieren
  zu müssen (Standardvorgehen bei Aggregatstatistiken).

### 4.6 Speicherfristen

Angelehnt an die bestehende 90-Tage-Konvention für Storage-Stats-Historie
(`docs/server-node-storage-stats-strategy.md`):

- Rohdaten-Batches (pro `telemetry_subject_id`, mit Zeitstempel): Vorschlag 180 Tage Aufbewahrung,
  danach automatische Löschung oder Reduktion auf grob aggregierte Zeitreihen ohne
  `telemetry_subject_id`-Bezug.
- Aggregierte/anonymisierte Fleet-Statistiken (z. B. "Ausfallrate je `hardware_profile_id` und
  Monat"): unbegrenzt aufbewahrbar, da nicht mehr personenbezogen, sofern die k-Anonymitäts-Schwelle
  aus 4.3 eingehalten wird.

## 5. Architektur des zentralen Statistiksammelservers

### 5.1 Bestehende zentrale Dienste als Vorbild

Der Code kennt aktuell zwei zentrale, von vielen Nodes/Clients angesprochene Dienste:

- `crates/rendezvous-server` — der einzige bestehende "viele Nodes/Clients sprechen mit einem
  zentralen Dienst"-Baustein im Projekt, mit HTTPS-Control-API, optionalem mTLS
  (`docs/security-architecture.md`, Abschnitt 4.2.1) und WebSocket-Relay.
- `crates/web-ui-backend` — ist dagegen kein zentraler Multi-Tenant-Dienst, sondern ein pro
  Client-Session laufendes Backend, das mit genau einem oder mehreren vom Nutzer verbundenen
  Server-Nodes spricht. Kein geeignetes Vorbild für einen fleet-weiten Sammler.

Der neue Statistiksammelserver ist funktional näher an `rendezvous-server` (viele unabhängige
Installationen sprechen mit einem zentralen, vom Projekt betriebenen Dienst) als an
`web-ui-backend`. Empfehlung: **ein neuer, eigenständiger Dienst** (z. B. `crates/stats-collector-server`)
statt eines Andockens an `web-ui-backend` oder `rendezvous-server` — beide bestehenden Dienste haben
ein anderes Vertrauens- und Betriebsmodell (Cluster-intern bzw. Verbindungsvermittlung), und eine
Vermischung mit fleet-weiter Telemetrie würde deren Sicherheitsgrenzen unnötig verkomplizieren.

### 5.2 Ingestion-Endpoint

- Protokoll: HTTPS (TLS 1.3), analog zu allen anderen Ironmesh-HTTP-Diensten.
- Auth: bewusst **kein** node-individuelles mTLS wie im Cluster-internen Fall — der Sammelserver soll
  gerade nicht wissen, welchem Cluster/Betreiber ein Datensatz zuzuordnen ist. Stattdessen:
  - kein Client-Identitätsnachweis über den `telemetry_subject_id` hinaus, der bereits Teil des
    Payloads ist,
  - Missbrauchsschutz über Rate-Limiting pro Quell-IP und pro `telemetry_subject_id` (nicht über
    Login/Token), plus eine einfache Plausibilitätsprüfung des Payload-Schemas.
  - Optional (offene Frage, Abschnitt 8): ein anonymes, bei der ersten Aktivierung einmalig
    ausgestelltes Ingestion-Token, um Spam/Fälschung zu erschweren, ohne Identität preiszugeben.
- Endpoint-Form: `POST /v1/ingest/hardware-reliability` mit dem in Abschnitt 7 skizzierten
  versionierten Payload.

### 5.3 Speicherung / Zugriffskontrolle

- Rohdaten-Ingestion: einfache, anhängende Speicherung (z. B. relationale DB oder Zeitreihen-Store)
  getrennt von der öffentlich zugänglichen Aggregat-Ansicht.
- Aggregation: periodischer Batch-Job, der Rohdaten zu k-anonymen Fleet-Statistiken je
  `hardware_profile_id` verdichtet (siehe 4.3).
- Für die Zeitreihen-Aggregation selbst ist, anders als bei der Einzel-Node-Storage-Stats-Historie
  (wo `docs/server-node-storage-stats-strategy.md` bewusst gegen eine externe Zeitreihen-DB pro Node
  entscheidet), ein dedizierter Zeitreihen-/Analyse-Store hier tatsächlich passend, weil es sich um
  *einen* zentralen Dienst statt vieler Einzel-Node-Instanzen handelt. Die im Storage-Stats-Dokument
  bereits notierte "GreptimeDB als künftiges zentrales Backend"-Idee passt hier besser als beim
  Node-lokalen Fall.
- Zugriffskontrolle:
  - Rohdaten (inkl. `telemetry_subject_id`-Zuordnung über Zeit): nur Projekt-Maintainer/Betreiber
    des Sammelservers, admin-authentifiziert analog zum bestehenden `IRONMESH_ADMIN_TOKEN`/RBAC-Modell
    aus `docs/security-architecture.md`.
  - Aggregierte, k-anonyme aufbereitete Statistiken: öffentlich einsehbar (z. B. künftiges
    "Fleet Reliability"-Dashboard), da genau das den Community-Nutzen dieser Funktion ausmacht.

### 5.4 Eigenständiger Dienst vs. bestehende Backend-Infrastruktur

Fazit: **neuer eigenständiger Dienst**, kein Andocken an `web-ui-backend` oder `server-admin`. Der
`server-node` selbst bekommt lediglich einen neuen ausgehenden Client (ähnlich den bestehenden
`RendezvousControlClient`-Mustern in `client-sdk`), der periodisch an den neuen Dienst sendet.

## 6. Übertragungsfrequenz/Batching

Angelehnt an die im Storage-Stats-Dokument etablierten Muster (Kombination aus periodischem Timer
und ereignisgesteuerter, entkoppelter Aktualisierung, mit Debouncing):

- Kein Echtzeitversand einzelner Findings — das würde unnötig Netzwerk-/Batterie-/CPU-Last erzeugen
  und widerspricht dem Grundsatz aus `docs/node-memory-footprint-reduction-plan.md` und dem
  Storage-Stats-Dokument, Hintergrundarbeit ressourcenschonend zu takten.
- Ein Batch fasst den aktuellen Stand des reduzierten `hardware_health_report`
  (siehe Abschnitt 2) zu einem Zeitpunkt zusammen, keine Ereignis-für-Ereignis-Übertragung.
- Vorschlag: fester periodischer Timer, analog zum bestehenden
  `HARDWARE_HEALTH_REFRESH_INTERVAL_SECS` (aktuell 5 Minuten für die node-lokale Aktualisierung),
  aber mit einem deutlich selteneren Sende-Intervall, z. B. alle 6–24 Stunden — die node-lokale
  Erfassung bleibt häufig (für Admin-UI-Frische), der externe Versand ist bewusst seltener, da nur
  Trends über Tage/Wochen relevant sind.
- Kein zusätzliches sofortiges Senden bei kritischen Findings in der ersten Ausbaustufe (Konsistenz
  mit dem konservativen "detect-only zuerst"-Ansatz aus `docs/data-scrub-auto-repair-strategy.md`);
  ein optionaler beschleunigter Versand bei neuen `critical`-Findings kann eine spätere Ausbaustufe
  sein.
- Retry/Backoff bei Sendefehlern analog zum bestehenden Replikations-Repair-Muster
  (`IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS` als Vorbild): fehlgeschlagene Batches werden verworfen
  oder mit begrenzter Anzahl Versuche später erneut versucht, nie unbegrenzt aufgestaut (kein
  unbeschränkt wachsender Sende-Puffer).
- Deduplizierung: wenn sich seit dem letzten erfolgreichen Versand nichts Wesentliches geändert hat
  (kein neues Finding, keine SMART-Werteänderung oberhalb einer Rausch-Schwelle), kann der Versand
  übersprungen werden, um Grundlast zu reduzieren — Detailschwelle ist Implementierungsdetail.

## 7. Datenschema-Versionierung/Erweiterbarkeit

- Jeder Payload trägt ein Top-Level-Feld `schema_version: u32`, beginnend bei `1`.
- Additive Evolution: neue Felder werden nur als optional hinzugefügt; bestehende Felder werden nicht
  umbenannt oder in ihrer Bedeutung geändert (bei Bedeutungsänderung: neue `schema_version`).
- Der Ingestion-Endpoint des zentralen Dienstes ist toleranz-first zu implementieren: unbekannte
  zusätzliche Felder werden ignoriert statt den Request abzulehnen (erlaubt älteren Servern, mit
  neueren Node-Versionen zu koexistieren, und umgekehrt).
- Analog zum bestehenden `collectors`-Statusfeld im `hardware_health_report` trägt auch dieser Payload
  pro Metrikgruppe einen `available: bool`/`collector_state`-Hinweis, damit der zentrale Dienst
  fehlende Werte von "bewusst nicht unterstützt" unterscheiden kann, statt Nullwerte zu interpretieren.
- Grobes Skizzenschema (Illustration, keine finale Spezifikation):

```jsonc
{
  "schema_version": 1,
  "telemetry_subject_id": "hex-hmac...",
  "generated_at_unix": 1752912000,
  "ironmesh_version": "1.0.33",
  "hardware_profile_id": "hp-...",   // wie im bestehenden hardware_health_report
  "node_lifecycle": {
    "uptime_seconds": 431200,
    "cumulative_observed_uptime_seconds": 9871200,
    "boot_count_observed": 7
  },
  "storage_devices": [
    {
      "component_instance_id": "ci-...", // bereits gehasht, siehe Hardware-Health-Doku
      "is_rotational": false,
      "interface_type": "nvme",
      "smart": {
        "smart_passed": true,
        "power_on_hours": 5011,
        "reallocated_sector_count": 0,
        "media_errors": 0,
        "percentage_used": 12
      }
    }
  ],
  "reliability_findings_summary": [
    { "finding_code": "chunk_hash_mismatch", "occurrence_count": 2 }
  ],
  "collectors": [
    { "collector_id": "smartctl", "available": true }
  ]
}
```

- Migrationspfad: alte `schema_version`-Payloads bleiben im Rohdatenspeicher unverändert lesbar;
  Aggregationsjobs müssen versionsbewusst normalisieren, bevor sie über mehrere `schema_version`-Werte
  hinweg aggregieren.

## 8. Offene Fragen / nächste Schritte

- **Juristische Prüfung vor Rollout:** Ist "aktiv per Default + Opt-out" für diese Datenkategorie in
  den relevanten Jurisdiktionen (insbesondere EU/DSGVO) rechtlich ausreichend, oder wird ein
  bestätigungspflichtiger erster Schritt im Setup-Flow benötigt (siehe 4.4)? Sollte vor Implementierung
  geklärt werden, nicht erst vor Release.
- **Betrieb des zentralen Dienstes:** Wer hostet/betreibt `stats-collector-server` produktiv, mit
  welchem Budget, welcher Domain, welchem Monitoring? Aktuell existiert dafür keine Infrastruktur im
  Projekt (anders als z. B. für `rendezvous-server`, falls dort bereits ein gehosteter Dienst existiert
  — zu verifizieren).
- **Rotation von `telemetry_subject_id`:** Fixiertes Intervall (z. B. 180 Tage) vs. nie rotierend vs.
  nutzergesteuert ("Reset-Button" in der Admin-UI)? Zielkonflikt zwischen Statistik-Kontinuität und
  Datenschutz muss entschieden werden.
- **Missbrauchsschutz ohne Identität:** Wie wird Spoofing/Spam am nicht-authentifizierten
  Ingestion-Endpoint verhindert, ohne ein De-Anonymisierungsrisiko durch Auth-Token einzuführen?
  Anonymes Ausstellungs-Token (Abschnitt 5.2) vs. reines IP-Rate-Limiting ist noch offen.
- **Granularität von Temperatur-/SMART-Zeitreihen:** Sollten Rohwerte je Batch übertragen werden oder
  bereits node-seitig auf Tagesaggregate (min/max/mean) reduziert werden, um sowohl Bandbreite zu
  sparen als auch das Fingerprinting-Risiko einzelner Geräte über feingranulare Zeitreihen zu
  reduzieren?
- **RAM-ECC- und CPU-MCE-Erfassung:** Lohnt sich der Zusatzaufwand für EDAC-/MCE-Auslesen angesichts
  der geringen Abdeckung auf Consumer-Hardware, oder wird das auf "Server-/Workstation-Board"-Nutzer
  beschränkt priorisiert (Abschnitt 2.4)?
- **Verhältnis zum bestehenden `/api/v1/auth/hardware/health`-Endpoint:** Soll der zu sendende Payload
  strikt als abgeleitete, einseitige Projektion aus dem bestehenden `hardware_health_report` erzeugt
  werden (ein Konverter, keine zweite unabhängige Erfassung), um Drift zwischen node-lokaler und
  zentral gesendeter Sicht zu vermeiden? Empfehlung: ja, sollte vor Implementierung als Vorgabe
  festgeschrieben werden.
- **Admin-UI-Platzierung:** Eigene neue `server-admin`-Seite/Settings-Sektion vs. Erweiterung der
  bestehenden `HardwarePage.tsx` — Entscheidung steht noch aus (Abschnitt 3.2 schlägt Erweiterung vor,
  aber Umfang der Einstellungen könnte eine eigene Settings-Seite rechtfertigen, falls künftig weitere
  Opt-out-Telemetrie-Kategorien dazukommen).
- **Cluster- vs. Node-Granularität des Opt-outs:** Aktuell als Per-Node-Einstellung skizziert
  (konsistent mit allen anderen Node-Env-Var-Togglen). Sollte stattdessen ein Cluster-weiter Default
  über die Control-Plane verteilt werden können, damit ein Betreiber nicht jeden Node einzeln
  umschalten muss? Deckt sich mit offenen Fragen zu Cluster-weiten Policy-Verteilungsmechanismen, die
  in `docs/multi-node-strategy.md` bereits für andere Policies angedeutet, aber nicht abschließend
  gelöst sind.
