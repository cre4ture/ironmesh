# Cockpit für die Host-Administration

## Entscheidung

Die IronMesh-Server-Admin-Oberfläche bleibt für IronMesh-Konfiguration,
Status und Datenbetrieb zuständig. Privilegierte Host-Aufgaben werden nicht
in IronMesh eingebaut, sondern durch Cockpit als getrennte
Host-Administrationsoberfläche erledigt:

- Neustart des von der Installation verwalteten IronMesh-Service,
- Betriebssystem- und Paket-Updates,
- Neustart oder Herunterfahren des Hosts.

Das passt besonders gut zu Hosts, auf denen der IronMesh Server Node der
einzige fachlich relevante Dienst ist, ohne der Anwendung selbst Root-Rechte
oder eine zusätzliche Privilegiengrenze geben zu müssen.

## Bedienablauf

Eine Änderung der Storage-Pool-Konfiguration wird erst beim Start eines Server
Nodes übernommen. Der Editor auf der Seite **Metadata** validiert die JSON-
Konfiguration serverseitig und speichert sie atomar in `storage-pool.json`.
Der laufende Node wird dabei absichtlich nicht umkonfiguriert. Nach dem
Speichern zeigt die Oberfläche deutlich an, dass ein Neustart erforderlich
ist. Der Operator führt diesen Neustart anschließend in seiner separat
abgesicherten Cockpit-Sitzung aus.

Cockpit wird nicht eingebettet, nicht per Reverse Proxy durch IronMesh
weitergereicht und erhält kein Single Sign-on oder Zugangstoken von IronMesh.
Damit bleiben die IronMesh-Admin-Anmeldung und die Host-Root-Verwaltung
getrennte Sicherheitsgrenzen.

## Dependencies-Check

Die Seite **Dependencies** prüft lokal, ob die Cockpit-Webservice-Binärdatei
`cockpit-ws` vorhanden und ausführbar ist. Zuerst wird sie über `PATH`
gesucht; auf Unix-Systemen folgen die üblichen Installationspfade
`/usr/lib/cockpit/cockpit-ws`, `/usr/libexec/cockpit-ws` und
`/usr/libexec/cockpit/cockpit-ws`.

Der Check ist rein lokal und lesend. Ein positiver Status bedeutet nur, dass
Cockpit installiert ist. Er prüft bewusst nicht, ob `cockpit.socket` aktiviert
ist, ein Port lauscht, eine Firewall den Zugriff erlaubt oder die Cockpit-Web-
Oberfläche von einem bestimmten Client erreichbar ist. Ein fehlender Check ist
als **optional** markiert und blockiert keine IronMesh-Funktion.

Die Detailkarte macht deutlich, dass Cockpit für Service-Neustarts, Updates
und Host-Reboots verwendet werden kann, IronMesh diese Aktionen jedoch weder
anfordert noch Zugangsdaten mit Cockpit teilt.

## Umsetzungsphasen

1. **Orientierung im bestehenden Admin-UI**
   - Cockpit-Erkennung auf der Seite **Dependencies**.
   - Optionaler Status und Installationshinweis ohne Auswirkung auf
     Funktionsprüfungen.
2. **Konfigurationsänderung in IronMesh**
   - Die Storage-Pool-Bearbeitung validiert ihre Eingabe gegen dieselben
     Konfigurationsregeln wie der Node-Start und speichert sie atomar.
   - Nach dem Speichern weist sie auf den erforderlichen Service-Neustart hin.
3. **Host-Operation in Cockpit**
   - Der Operator öffnet Cockpit über den für seine Umgebung vorgesehenen,
     separat geschützten Zugang und führt dort den Neustart oder die
     Host-Wartung aus.

Alle drei Phasen sind mit dieser Änderung abgedeckt. Die Trennung zwischen
Anwendungsverwaltung und Host-Administration bleibt dabei erhalten und
benötigt keinen privilegierten IronMesh-Endpunkt.
