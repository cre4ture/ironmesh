# Ironmesh Android (initial MVP)

This is a standalone Kotlin Android app scaffold for local testing of `server-node`.

## Features (MVP)

- Set server base URL
- Health check (`GET /health`)
- Replication plan summary (`GET /cluster/replication/plan`)
- Upload object (`PUT /store/{key}`)
- Download object (`GET /store/{key}`)

## Open in Android Studio

Open this folder as a project:

- `apps/android-app/native`

Android Studio will sync Gradle and let you run the `app` module.

## Local server notes

For Android emulator, use:

- `http://10.0.2.2:18080`

For a physical device, use your host machine LAN IP.

## Cleartext HTTP

The app currently allows cleartext traffic (`usesCleartextTraffic=true`) for local development.
