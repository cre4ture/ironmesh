# Mehrere lokale Storage-Pfade

## Ziel und Rahmen

Ein Server-Node kann seine unveränderlichen Nutzdaten auf mehrere lokale
Dateisysteme verteilen. Das betrifft ausschließlich Content-Addressed-Daten:

- Chunks unter `chunks/`,
- Objekt-Manifeste unter `manifests/`.

Die Node-Steuerdaten bleiben bewusst an einem Ort unter `IRONMESH_DATA_DIR`:
Metadaten-Datenbank, Identität, TLS-Material, Snapshots, Caches und die
Storage-Pool-Konfiguration. Damit bleiben ein Node und seine administrativen
Metadaten als Einheit portierbar, ohne dass ein Enrollment-Paket
host-spezifische Mount-Pfade enthalten muss.

Dies ist kein Cluster-Replikationsmechanismus. Ein Chunk liegt innerhalb eines
Nodes weiterhin genau auf einem lokalen Pfad; Redundanz zwischen Nodes wird
weiterhin durch die bestehende Replikation erreicht.

## Konfiguration

Ohne Konfiguration bleibt das bisherige Verhalten vollständig erhalten:
`IRONMESH_DATA_DIR` ist der einzige, aktive Pfad für Chunks und Manifeste.

Für mehrere Pfade wird beim Node eine JSON-Datei abgelegt:

```text
${IRONMESH_DATA_DIR}/state/storage-pool.json
```

Für getrennte Betriebs- und Konfigurationspfade kann sie mit
`IRONMESH_STORAGE_CONFIG=/etc/ironmesh/storage-pool.json` überschrieben
werden. Änderungen werden beim Node-Start eingelesen; für eine geänderte
Konfiguration ist daher ein geordneter Neustart nötig.

Beispiel für einen neu eingerichteten Node:

```json
{
  "version": 1,
  "paths": [
    {
      "id": "ssd-a",
      "path": "/srv/ironmesh-a",
      "state": "active",
      "weight": 1,
      "reserve_bytes": 21474836480
    },
    {
      "id": "ssd-b",
      "path": "/srv/ironmesh-b",
      "state": "active",
      "weight": 1,
      "reserve_bytes": 21474836480
    }
  ]
}
```

- `id` ist dauerhaft, eindeutig und besteht aus ASCII-Buchstaben, Ziffern,
  `-` oder `_`.
- `path` muss beim Start ein vorhandenes, beschreibbares Verzeichnis sein.
  Nicht eingehängte konfigurierte Pfade werden im Status als nicht verfügbar
  gemeldet und nehmen keine neuen Daten an.
- `weight` steuert die bevorzugte Belegung relativ zu den anderen aktiven
  Pfaden. Der Standard ist `1`.
- `reserve_bytes` hält freien Platz für Betriebssystem und Operatoren zurück.
- Pfade dürfen sich nicht überlappen und dürfen nicht von mehreren Nodes
  verwendet werden.

Beim ersten Einsatz wird in jedem Pfad ein Marker
`.ironmesh-storage-path.json` angelegt. Er bindet den Pfad an Node und
Pfad-ID, damit versehentlich gemeinsam verwendete oder vertauschte Mounts beim
Start auffallen.

### Umstellung eines bestehenden Ein-Pfad-Nodes

Der bisherige Datenpfad bleibt lesbar, auch wenn keine Konfigurationsdatei
existiert. Wird er in eine explizite Pool-Konfiguration übernommen, muss seine
bestehende Kennung `legacy-primary` beibehalten werden:

```json
{
  "version": 1,
  "paths": [
    {
      "id": "legacy-primary",
      "path": "/var/lib/ironmesh/server-node",
      "state": "active"
    },
    {
      "id": "ssd-b",
      "path": "/srv/ironmesh-b",
      "state": "active"
    }
  ]
}
```

Das bewahrt den Marker des bisherigen Standardpfads. Neue Daten werden danach
über beide aktiven Pfade verteilt; vorhandene, noch nicht indizierte Daten auf
`legacy-primary` bleiben lesbar.

## Platzierung und Lookup

Beim erstmaligen Schreiben eines Chunks oder Manifests wählt der Node einen
aktiven, erreichbaren Pfad mit genügend freiem Platz über `reserve_bytes`.
Eine gewichtete, kapazitätsbewusste Hash-Auswahl hält die Wahl für denselben
Content stabil und verteilt neue Daten nach Gewicht und verfügbarem Platz.

Die Wahl wird zusammen mit dem Content-Typ und Hash in der bestehenden lokalen
Metadaten-Datenbank gespeichert. Beim Start lädt der Node diese Zuordnung in
zwei speichereffiziente Hash-Maps (Chunk und Manifest). Ein normaler
Chunk-Lookup braucht damit keine SQLite-/Turso-Abfrage und keine zusätzliche
Netzwerkoperation: Er besteht aus einem In-Memory-Map-Lookup und dem ohnehin
notwendigen Dateizugriff. Bei alten, noch nicht indizierten Daten fällt der
Lookup auf den bisherigen Primärpfad zurück.

Schreib- und Umzugsvorgänge sind absturzsicher in zwei Phasen:

1. Die Zuordnung wird als `pending` persistiert.
2. Die Datei wird atomar geschrieben, die Zuordnung auf `available` gesetzt
   und in den Speicherindex übernommen.

Beim nächsten Start werden stehengebliebene `pending`-Einträge anhand von
Größe und BLAKE3-Hash validiert und entweder aktiviert oder entfernt.

## Betrieb und Rebalancing

Der Admin-Endpunkt `GET /api/v1/auth/storage/pool` und die Server-Admin-Seite
zeigen Konfigurationspfad, Zustand, Kapazität, freien Platz und belegte
Chunk-/Manifest-Bytes pro Pfad.

Für eine geordnete Außerbetriebnahme wird ein Pfad auf `draining` gesetzt und
der Node neu gestartet. Neue Daten werden dann nicht mehr auf diesem Pfad
geschrieben. Anschließend verschiebt
`POST /api/v1/auth/storage/pool/rebalance` alle gültigen Chunks und Manifeste
auf aktive Pfade. Die Ziel-Datei und ihre Metadaten-Zuordnung werden zuerst
persistiert, erst danach wird die Quelldatei entfernt. Der Vorgang kann nach
einem Fehler erneut gestartet werden.

`disabled` nimmt ebenfalls keine neuen Daten an und wird nicht für die
aggregierte Node-Kapazität gezählt. Ein deaktivierter Pfad ist kein
Ersatz für `draining`, solange er noch die einzige lokale Kopie von Daten
enthält.

## Umsetzungsphasen und Abnahme

1. **Datenmodell und kompatible Konfiguration**
   - Pool-Konfiguration, Pfad-Zustände, Kapazitätsreserve und Pfad-Marker.
   - Impliziter `legacy-primary`-Pfad ohne Konfigurationsdatei.
2. **Persistente Standortzuordnung**
   - `storage_locations` in SQLite und Turso.
   - In-Memory-Index beim Start sowie Recovery von unterbrochenen Writes.
3. **Alle Content-Zugriffe poolfähig machen**
   - Objekt-Reads, Uploads, Replication, Streaming, Media-Cache, Data-Scrub,
     Garbage Collection und Storage-Stats verwenden den Pool.
4. **Betriebsschnittstellen**
   - Aggregierte Node-Kapazität, Pfad-Status, Rebalance-Endpunkt und
     Server-Admin-Ansicht.
5. **Qualitätssicherung**
   - Tests für Legacy-Modus, Verteilung/Neustart, Draining-Rebalance,
     Konfigurationsvalidierung und beide Metadaten-Backends.
   - Rust-Formatierung, Rust-Tests und Frontend-Build.

Die Implementierung dieser Phasen gehört zusammen: Der Speicherindex sorgt
dafür, dass die zusätzliche Indirektion im normalen Chunk-Lookup nicht zu
einem Datenbank-Roundtrip wird, während die persistente Zuordnung und die
Recovery den Betrieb nach Neustarts und Teilfehlern korrekt halten.
