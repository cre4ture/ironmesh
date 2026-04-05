import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { expect, test, type Page, type Route } from "@playwright/test";

test("server-admin runtime smoke flow renders and navigates", async ({ page }) => {
  await installServerAdminMocks(page);

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Version info", { exact: true })).toBeVisible();
  await expect(page.getByText(/UI build:\s*0\.1\.0 \(/)).toBeVisible();
  await expect(page.getByText("Backend build: 0.1.0 (v0.1.0-5-gmocked)")).toBeVisible();
  await expect(page.getByText("0 discovered")).toBeVisible();
  await expect(page.getByText("runtime ready")).toBeVisible();
  await expect(page.getByText("This node", { exact: true })).toBeVisible();
  await expect(page.getByText("Rendezvous participation", { exact: true })).toBeVisible();
  await expect(page.getByText("Storage stats", { exact: true })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Collected at (UTC)" })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Storage used (bytes)" })).toBeVisible();
  await expect(page.getByRole("button", { name: "30d", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "All", exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Chunk Store" })).toBeVisible();
  await expect(page.getByText("Latest snapshot ID:")).toBeVisible();
  await expect(page.getByText("Snapshot logical size:")).toBeVisible();
  await expect(page.getByText("Sign in or provide an admin token override to inspect the live rendezvous registration details here.")).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("cell", { name: "node-alpha", exact: true })).toBeVisible();
  await expect(page.locator("td").filter({ hasText: /logical/ }).first()).toBeVisible();
  await expect(page.getByRole("code").filter({ hasText: "https://node-alpha.local" })).toBeVisible();
  await expect(
    page
      .getByRole("paragraph")
      .filter({ hasText: "Embedded listener: https://embedded-rendezvous.local:9443" })
      .getByRole("code")
  ).toBeVisible();

  await page.getByText("Provisioning", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Provisioning" })).toBeVisible();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();
  await expect(page.getByAltText("Client bootstrap QR code")).toBeVisible();

  await page.getByLabel("Node join request JSON").fill(
    JSON.stringify({
      version: 1,
      node_id: "node-beta",
      cluster_id: "cluster-alpha"
    })
  );
  await page.getByRole("button", { name: "Issue enrollment package" }).click();
  await expect(page.getByText("internal_tls_material")).toBeVisible();

  await page.getByText("Credentials", { exact: true }).click();
  await expect(page.getByRole("cell", { name: "client-credential-a", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke" }).first().click();
  await page.getByLabel("Revocation reason").fill("manual smoke revocation");
  await page.getByRole("button", { name: "Revoke credential" }).click();
  await expect(page.getByText("manual smoke revocation")).toBeVisible();

  await page.getByText("Certificates", { exact: true }).click();
  await expect(page.getByText("Fingerprint: internal-cert-fingerprint", { exact: true })).toBeVisible();

  await page.getByText("Logs", { exact: true }).click();
  await expect(page.getByText("replication audit healthy")).toBeVisible();

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByText("gallery/cat.png", { exact: true })).toBeVisible();
  await expect(page.getByText("2 photos", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Map" }).click();
  await expect(
    page.getByText("Using MapTiler Satellite 2017-11-02 Planet from your self-hosted basemap dataset.")
  ).toBeVisible();
  await expect(page.getByText("Self-hosted basemap unavailable")).toHaveCount(0);
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("2 markers")).toBeVisible();
  await page.getByRole("button", { name: "Open map marker for gallery/cat.png" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Loading original image")).toBeVisible();
  await expect(page.getByText("Loading original image")).toHaveCount(0);
  await page.getByRole("button", { name: "Next item" }).click();
  await expect(page.getByRole("dialog").getByText("gallery/dog.jpg", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Setup", { exact: true }).click();
  await expect(page.getByText("Bootstrap setup APIs are not active on this node")).toBeVisible();

  await page.getByText("Control Plane", { exact: true }).click();
  await expect(page.getByText("https://embedded-rendezvous.local:9443", { exact: true })).toBeVisible();
  await page
    .getByRole("textbox", { name: "Editable operator-managed URLs" })
    .fill("https://rendezvous-a.local:9443\nhttps://rendezvous-b.local:9443");
  await page.getByRole("button", { name: "Save rendezvous URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "rendezvous-b.local:9443" }).first()).toBeVisible();

  await page.getByRole("textbox", { name: "Target node ID" }).first().fill("node-beta");
  await page.getByLabel("Passphrase").first().fill("rendezvous-passphrase");
  await page.getByRole("button", { name: "Export rendezvous failover package" }).click();
  await expect(page.getByText("https://node-beta.local/rendezvous")).toBeVisible();

  const rendezvousPackageJson = JSON.stringify({
    version: 1,
    cluster_id: "cluster-alpha",
    source_node_id: "node-alpha",
    target_node_id: "node-beta",
    public_url: "https://node-beta.local/rendezvous"
  });
  await page.getByLabel("Rendezvous failover package JSON").fill(rendezvousPackageJson);
  await page.getByLabel("Passphrase").nth(1).fill("rendezvous-passphrase");
  await page.getByRole("button", { name: "Import rendezvous failover package" }).click();
  await expect(page.getByText("tls/rendezvous.key")).toBeVisible();

  await page.getByRole("textbox", { name: "Target node ID" }).nth(1).fill("node-beta");
  await page.getByLabel("Passphrase").nth(2).fill("promotion-passphrase");
  await page.getByRole("button", { name: "Export promotion package" }).click();
  await expect(page.getByText("signer_backup")).toBeVisible();

  const packageJson = JSON.stringify({
    signer_backup: { version: 1, from: "node-alpha" },
    rendezvous_failover: { version: 1, to: "node-beta" }
  });
  await page.getByLabel("Promotion package JSON").fill(packageJson);
  await page.getByLabel("Passphrase").nth(3).fill("promotion-passphrase");
  await page.getByRole("button", { name: "Import promotion package" }).click();
  await expect(page.getByText("tls/cluster-ca.pem")).toBeVisible();
});

test("server-admin provisioning can target a selected rendezvous service", async ({ page }) => {
  await installServerAdminMocks(page);

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByLabel("Preferred rendezvous service").selectOption("https://rendezvous-a.local:9443/");
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.locator("pre").filter({ hasText: '"rendezvous_url": "https://rendezvous-a.local:9443/"' })).toBeVisible();
  await expect(page.getByText("Request failed", { exact: true })).toHaveCount(0);
});

test("server-admin provisioning falls back to the full bootstrap bundle when claim issuance returns 502", async ({ page }) => {
  await installServerAdminMocks(page, { bootstrapClaimMode: "bad_gateway" });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.getByText("Compact claim issuance is temporarily unavailable on this node, so the page fell back to a full bootstrap QR.")).toBeVisible();
  await expect(page.getByText("Scan the full bootstrap bundle with the ironmesh Android app")).toBeVisible();
  await expect(page.getByAltText("Client bootstrap QR code")).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();
  await expect(page.getByText("Request failed", { exact: true })).toHaveCount(0);
});

test("server-admin provisioning does not fall back when a specific rendezvous service is selected", async ({ page }) => {
  await installServerAdminMocks(page, { bootstrapClaimMode: "bad_gateway" });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByLabel("Preferred rendezvous service").selectOption("https://rendezvous-a.local:9443/");
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.getByText("Request failed", { exact: true })).toBeVisible();
  await expect(page.getByText("Compact claim issuance is temporarily unavailable on this node, so the page fell back to a full bootstrap QR.")).toHaveCount(0);
});

test("server-admin runtime ignores auth-protected setup probes", async ({ page }) => {
  await installServerAdminMocks(page, { setupProbeStatus: 401 });

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Setup probe warning", { exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await expect(page.getByText("Setup probe warning", { exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape");

  await page.getByText("Setup", { exact: true }).click();
  await expect(page.getByText("Bootstrap setup APIs are not active on this node")).toBeVisible();
  await expect(page.getByText("Setup endpoint error", { exact: true })).toHaveCount(0);
});

async function installServerAdminMocks(
  page: Page,
  options?: {
    setupMode?: boolean;
    bootstrapClaimMode?: "success" | "bad_gateway";
    setupProbeStatus?: 401 | 403 | 404;
  }
) {
  const imageBody = tinyPngBuffer();
  const logicalMapBody = readFileSync("tests/fixtures/smoke.mbtiles");
  const emptyVectorTileBody = gzipSync(Buffer.alloc(0));
  const glyphRangeBody = Buffer.alloc(0);
  let authenticated = false;
  const revokedDeviceIds = new Set<string>();
  const bootstrapBundle = {
    cluster_id: "cluster-alpha",
    relay_mode: "relay-preferred",
    rendezvous_mtls_required: true,
    rendezvous_urls: ["https://node-alpha.local/rendezvous"],
    direct_endpoints: [
      {
        url: "https://node-alpha.local",
        usage: "public_api",
        node_id: "node-alpha"
      }
    ],
    trust_roots: {
      cluster_ca_pem: "-----BEGIN CERTIFICATE-----\\ncluster\\n-----END CERTIFICATE-----"
    }
  };
  let rendezvousConfig = {
    effective_urls: ["https://embedded-rendezvous.local:9443", "https://rendezvous-a.local:9443"],
    editable_urls: ["https://rendezvous-a.local:9443"],
    managed_embedded_url: "https://embedded-rendezvous.local:9443",
    registration_enabled: true,
    registration_interval_secs: 30,
    disconnected_retry_interval_secs: 5,
    endpoint_registrations: [
      {
        url: "https://embedded-rendezvous.local:9443",
        status: "connected",
        last_attempt_unix: 1_900_000_000,
        last_success_unix: 1_900_000_000,
        consecutive_failures: 0,
        last_error: null
      },
      {
        url: "https://rendezvous-a.local:9443",
        status: "connected",
        last_attempt_unix: 1_900_000_010,
        last_success_unix: 1_900_000_010,
        consecutive_failures: 0,
        last_error: null
      }
    ],
    mtls_required: true,
    persistence_source: "node_enrollment",
    persisted: true
  };

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const { pathname, searchParams } = url;
    const method = route.request().method();

    if (pathname === "/auth/admin/session" && method === "GET") {
      return json(route, {
        login_required: true,
        authenticated,
        session_expires_at_unix: authenticated ? 1_900_000_000 : null,
        token_override_enabled: true
      });
    }

    if (pathname === "/auth/admin/login" && method === "POST") {
      authenticated = true;
      return json(route, { status: "ok" });
    }

    if (pathname === "/auth/admin/logout" && method === "POST") {
      authenticated = false;
      return json(route, { status: "ok" });
    }

    if (pathname === "/auth/store/snapshots" && method === "GET") {
      return json(route, [{ id: "snapshot-admin-001" }]);
    }

    if (pathname === "/auth/store/index" && method === "GET") {
      expect(searchParams.get("view")).toBe("tree");
      return json(route, {
        prefix: searchParams.get("prefix") ?? "",
        depth: Number(searchParams.get("depth") ?? "1"),
        entry_count: 4,
        entries: [
          { path: "docs/readme.txt", entry_type: "key" },
          { path: "media/", entry_type: "prefix" },
          {
            path: "gallery/cat.png",
            entry_type: "key",
            media: {
              status: "ready",
              content_fingerprint: "fingerprint-cat",
              media_type: "image",
              mime_type: "image/png",
              width: 1024,
              height: 768,
              taken_at_unix: 1_712_345_678,
              gps: {
                latitude: 47.3769,
                longitude: 8.5417
              },
              thumbnail: {
                url: "/auth/media/thumbnail?key=gallery%2Fcat.png",
                profile: "grid",
                width: 256,
                height: 192,
                format: "jpeg",
                size_bytes: 1234
              }
            }
          },
          {
            path: "gallery/dog.jpg",
            entry_type: "key",
            media: {
              status: "pending",
              content_fingerprint: "fingerprint-dog",
              media_type: "image",
              mime_type: "image/jpeg",
              gps: {
                latitude: 40.7128,
                longitude: -74.006
              },
              thumbnail: {
                url: "/auth/media/thumbnail?key=gallery%2Fdog.jpg",
                profile: "grid",
                width: 256,
                height: 256,
                format: "jpeg",
                size_bytes: 0
              }
            }
          }
        ]
      });
    }

    if (pathname === "/auth/media/thumbnail" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "image/png",
        body: imageBody
      });
      return;
    }

    if (pathname.startsWith("/auth/store/") && method === "GET") {
      if (pathname === "/auth/store/gallery%2Fcat.png") {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      await route.fulfill({
        status: 200,
        contentType: "image/png",
        body: imageBody
      });
      return;
    }

    if (pathname === "/api/maps/logical-file") {
      const rangeHeader = route.request().headers().range;
      const commonHeaders = {
        "accept-ranges": "bytes",
        "content-type": "application/octet-stream",
        etag: "\"server-admin-smoke-mbtiles\""
      };

      if (method === "HEAD") {
        await route.fulfill({
          status: 200,
          headers: {
            ...commonHeaders,
            "content-length": String(logicalMapBody.length)
          }
        });
        return;
      }

      if (method === "GET") {
        if (!rangeHeader) {
          await route.fulfill({
            status: 200,
            headers: {
              ...commonHeaders,
              "content-length": String(logicalMapBody.length)
            },
            body: logicalMapBody
          });
          return;
        }

        const match = /^bytes=(\d+)-(\d+)?$/i.exec(rangeHeader);
        expect(match).not.toBeNull();
        const start = Number(match?.[1] ?? "0");
        const inclusiveEnd = Math.min(
          Number(match?.[2] ?? String(logicalMapBody.length - 1)),
          logicalMapBody.length - 1
        );
        const sliced = logicalMapBody.subarray(start, inclusiveEnd + 1);
        await route.fulfill({
          status: 206,
          headers: {
            ...commonHeaders,
            "content-length": String(sliced.length),
            "content-range": `bytes ${start}-${inclusiveEnd}/${logicalMapBody.length}`
          },
          body: sliced
        });
        return;
      }
    }

    if (pathname === "/api/maps/mbtiles-metadata" && method === "GET") {
      return json(route, {
        attribution: "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors.",
        center: [0, 20, 1],
        format: "png",
        minzoom: 0,
        maxzoom: 2
      });
    }

    if (pathname.startsWith("/api/maps/tiles/") && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "image/png",
          "cache-control": "public, max-age=3600"
        },
        body: imageBody
      });
      return;
    }

    if (pathname.startsWith("/api/maps/vector-tiles/") && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/vnd.mapbox-vector-tile",
          "content-encoding": "gzip",
          "cache-control": "public, max-age=3600"
        },
        body: emptyVectorTileBody
      });
      return;
    }

    if (pathname.startsWith("/api/maps/fonts/") && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/x-protobuf",
          "cache-control": "public, max-age=3600"
        },
        body: glyphRangeBody
      });
      return;
    }

    if (pathname === "/cluster/status" && method === "GET") {
      return json(route, {
        local_node_id: "node-alpha",
        total_nodes: 2,
        online_nodes: 2,
        offline_nodes: 0,
        policy: {
          replication_factor: 2,
          min_distinct_labels: {},
          accepted_over_replication_items: 0
        }
      });
    }

    if (pathname === "/cluster/nodes" && method === "GET") {
      return json(route, [
        {
          node_id: "node-alpha",
          reachability: {
            public_api_url: "https://node-alpha.local",
            peer_api_url: "https://node-alpha-peer.local",
            relay_required: false
          },
          capabilities: {
            public_api: true,
            peer_api: true,
            relay_tunnel: true
          },
          labels: {
            region: "lab"
          },
          capacity_bytes: 2_000_000_000,
          free_bytes: 1_250_000_000,
          storage_stats: {
            collected_at_unix: 1_900_000_100,
            latest_snapshot_id: "snapshot-node-alpha",
            latest_snapshot_created_at_unix: 1_900_000_090,
            latest_snapshot_object_count: 12,
            chunk_store_bytes: 1_024,
            manifest_store_bytes: 256,
            metadata_db_bytes: 512,
            media_cache_bytes: 256,
            latest_snapshot_logical_bytes: 8_192,
            latest_snapshot_unique_chunk_bytes: 4_096
          },
          last_heartbeat_unix: 1_900_000_000,
          status: "online"
        },
        {
          node_id: "node-beta",
          reachability: {
            public_api_url: null,
            peer_api_url: null,
            relay_required: true
          },
          capabilities: {
            public_api: true,
            peer_api: true,
            relay_tunnel: true
          },
          labels: {
            region: "lab"
          },
          capacity_bytes: 2_500_000_000,
          free_bytes: 1_500_000_000,
          storage_stats: {
            collected_at_unix: 1_900_000_110,
            latest_snapshot_id: "snapshot-node-beta",
            latest_snapshot_created_at_unix: 1_900_000_095,
            latest_snapshot_object_count: 14,
            chunk_store_bytes: 2_048,
            manifest_store_bytes: 512,
            metadata_db_bytes: 1_024,
            media_cache_bytes: 512,
            latest_snapshot_logical_bytes: 16_384,
            latest_snapshot_unique_chunk_bytes: 12_288
          },
          last_heartbeat_unix: 1_900_000_010,
          status: "online"
        }
      ]);
    }

    if (pathname === "/cluster/replication/plan" && method === "GET") {
      return json(route, {
        generated_at_unix: 1_900_000_005,
        under_replicated: 1,
        over_replicated: 0,
        cleanup_deferred_items: 0,
        cleanup_deferred_extra_nodes: 0,
        items: [
          {
            key: "photos/cover.jpg",
            desired_nodes: ["node-alpha", "node-beta"],
            current_nodes: ["node-alpha"],
            missing_nodes: ["node-beta"],
            extra_nodes: [],
            cleanup_option: "none",
            deferred_extra_nodes: 0
          }
        ]
      });
    }

    if (pathname === "/cluster/replication/repair" && method === "POST") {
      return json(route, {
        status: "repair-triggered",
        repaired_items: 1
      });
    }

    if (pathname === "/logs" && method === "GET") {
      return json(route, {
        entries: [
          "2026-03-19T17:00:00Z INFO runtime ready",
          "2026-03-19T17:00:02Z INFO replication audit healthy"
        ]
      });
    }

    if (pathname === "/health" && method === "GET") {
      return json(route, {
        node_id: "node-alpha",
        role: "server-node",
        online: true,
        version: "0.1.0",
        revision: "v0.1.0-5-gmocked"
      });
    }

    if (pathname === "/storage/stats/current" && method === "GET") {
      return json(route, {
        sample: {
          collected_at_unix: 1_900_000_120,
          latest_snapshot_id: "snapshot-9",
          latest_snapshot_created_at_unix: 1_900_000_100,
          latest_snapshot_object_count: 42,
          chunk_store_bytes: 1_234_000_000,
          manifest_store_bytes: 12_000_000,
          metadata_db_bytes: 4_000_000,
          media_cache_bytes: 8_000_000,
          latest_snapshot_logical_bytes: 2_468_000_000,
          latest_snapshot_unique_chunk_bytes: 1_100_000_000
        },
        collecting: false,
        last_attempt_unix: 1_900_000_120,
        last_success_unix: 1_900_000_120,
        last_error: null
      });
    }

    if (pathname === "/storage/stats/history" && method === "GET") {
      expect(searchParams.get("max_points")).toBe("360");
      expect(searchParams.get("since_unix")).not.toBeNull();
      return json(route, [
        {
          collected_at_unix: 1_900_000_120,
          latest_snapshot_id: "snapshot-9",
          latest_snapshot_created_at_unix: 1_900_000_100,
          latest_snapshot_object_count: 42,
          chunk_store_bytes: 1_234_000_000,
          manifest_store_bytes: 12_000_000,
          metadata_db_bytes: 4_000_000,
          media_cache_bytes: 8_000_000,
          latest_snapshot_logical_bytes: 2_468_000_000,
          latest_snapshot_unique_chunk_bytes: 1_100_000_000
        },
        {
          collected_at_unix: 1_900_000_060,
          latest_snapshot_id: "snapshot-8",
          latest_snapshot_created_at_unix: 1_900_000_040,
          latest_snapshot_object_count: 40,
          chunk_store_bytes: 1_190_000_000,
          manifest_store_bytes: 11_500_000,
          metadata_db_bytes: 3_900_000,
          media_cache_bytes: 7_500_000,
          latest_snapshot_logical_bytes: 2_310_000_000,
          latest_snapshot_unique_chunk_bytes: 1_070_000_000
        },
        {
          collected_at_unix: 1_900_000_000,
          latest_snapshot_id: "snapshot-7",
          latest_snapshot_created_at_unix: 1_899_999_980,
          latest_snapshot_object_count: 38,
          chunk_store_bytes: 1_120_000_000,
          manifest_store_bytes: 11_200_000,
          metadata_db_bytes: 3_800_000,
          media_cache_bytes: 7_200_000,
          latest_snapshot_logical_bytes: 2_210_000_000,
          latest_snapshot_unique_chunk_bytes: 1_020_000_000
        }
      ]);
    }

    if (pathname === "/setup/status" && method === "GET" && options?.setupMode) {
      return json(route, {
        state: "pending_join",
        data_dir: "/tmp/ironmesh-node-beta",
        bind_addr: "0.0.0.0:8443",
        bootstrap_tls_cert_path: "/tmp/bootstrap.pem",
        bootstrap_tls_fingerprint: "setup-fingerprint",
        cluster_id: null,
        node_id: "node-beta",
        pending_join_request: {
          version: 1,
          node_id: "node-beta",
          cluster_id: "cluster-alpha"
        }
      });
    }

    if (pathname === "/setup/status" && method === "GET") {
      const status = options?.setupProbeStatus ?? 404;
      if (status === 404) {
        await route.fulfill({
          status,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({ error: "setup mode not active" })
        });
        return;
      }

      await route.fulfill({ status });
      return;
    }

    if (pathname === "/setup/start-cluster" && method === "POST") {
      return json(route, {
        status: "transitioning_to_online",
        cluster_id: "cluster-new",
        node_id: "node-new",
        public_url: "https://node-new.local",
        restart_required: false
      });
    }

    if (pathname === "/setup/join/request" && method === "POST") {
      return json(route, {
        version: 1,
        node_id: "node-beta",
        cluster_id: "cluster-alpha"
      });
    }

    if (pathname === "/setup/join/import" && method === "POST") {
      return json(route, {
        status: "transitioning_to_online",
        cluster_id: "cluster-alpha",
        node_id: "node-beta",
        public_url: "https://node-beta.local",
        restart_required: false
      });
    }

    if (pathname === "/auth/bootstrap-claims/issue" && method === "POST") {
      const body = route.request().postDataJSON() as { preferred_rendezvous_url?: string | null };
      if (options?.bootstrapClaimMode === "bad_gateway") {
        await route.fulfill({
          status: 502
        });
        return;
      }

      return json(route, {
        bootstrap_bundle: bootstrapBundle,
        bootstrap_claim: {
          version: 1,
          kind: "client_bootstrap_claim",
          cluster_id: "cluster-alpha",
          rendezvous_url:
            typeof body.preferred_rendezvous_url === "string" && body.preferred_rendezvous_url.trim().length > 0
              ? new URL(body.preferred_rendezvous_url).toString()
              : "https://node-alpha.local/rendezvous",
          claim_token: "im-claim-example",
          expires_at_unix: 1_900_003_600,
          trust: {
            mode: "rendezvous_ca_der_b64u",
            ca_der_b64u: "TUlJQy4uLg"
          }
        }
      });
    }

    if (pathname === "/auth/bootstrap-bundles/issue" && method === "POST") {
      return json(route, bootstrapBundle);
    }

    if (pathname === "/auth/node-join-requests/issue-enrollment" && method === "POST") {
      return json(route, {
        bootstrap: {
          cluster_id: "cluster-alpha"
        },
        public_tls_material: {
          cert_pem: "public-cert"
        },
        internal_tls_material: {
          cert_pem: "internal-cert"
        }
      });
    }

    if (pathname === "/auth/client-credentials" && method === "GET") {
      return json(route, buildCredentialList(revokedDeviceIds));
    }

    if (pathname === "/auth/rendezvous-config" && method === "GET") {
      return json(route, rendezvousConfig);
    }

    if (pathname === "/auth/rendezvous-config" && method === "PUT") {
      const body = route.request().postDataJSON() as { editable_urls?: string[] };
      rendezvousConfig = {
        ...rendezvousConfig,
        editable_urls: body.editable_urls ?? [],
        effective_urls: [
          "https://embedded-rendezvous.local:9443",
          ...(body.editable_urls ?? [])
        ]
      };
      return json(route, rendezvousConfig);
    }

    if (pathname.startsWith("/auth/client-credentials/") && method === "DELETE") {
      revokedDeviceIds.add(decodeURIComponent(pathname.split("/").pop() ?? ""));
      return json(route, { status: "revoked" });
    }

    if (pathname === "/auth/node-certificates/status" && method === "GET") {
      return json(route, {
        public_tls: {
          name: "public",
          configured: true,
          cert_path: "tls/public.pem",
          metadata_path: "tls/public.meta.json",
          issued_at_unix: 1_900_000_000,
          renew_after_unix: 1_900_100_000,
          expires_at_unix: 1_900_200_000,
          seconds_until_expiry: 200_000,
          certificate_fingerprint: "public-cert-fingerprint",
          metadata_matches_certificate: true,
          state: "healthy"
        },
        internal_tls: {
          name: "internal",
          configured: true,
          cert_path: "tls/internal.pem",
          metadata_path: "tls/internal.meta.json",
          issued_at_unix: 1_900_000_000,
          renew_after_unix: 1_900_100_000,
          expires_at_unix: 1_900_200_000,
          seconds_until_expiry: 200_000,
          certificate_fingerprint: "internal-cert-fingerprint",
          metadata_matches_certificate: true,
          state: "healthy"
        },
        auto_renew: {
          enabled: true,
          enrollment_path: "node-enrollment.json",
          issuer_url: "https://node-alpha.local",
          check_interval_secs: 300,
          last_attempt_unix: 1_900_000_050,
          last_success_unix: 1_900_000_040,
          last_error: null,
          restart_required: false
        }
      });
    }

    if (pathname === "/auth/managed-control-plane/promotion/export" && method === "POST") {
      return json(route, {
        signer_backup: {
          version: 1,
          from: "node-alpha"
        },
        rendezvous_failover: {
          version: 1,
          to: "node-beta"
        }
      });
    }

    if (pathname === "/auth/managed-rendezvous/failover/export" && method === "POST") {
      return json(route, {
        version: 1,
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        target_node_id: "node-beta",
        public_url: "https://node-beta.local/rendezvous"
      });
    }

    if (pathname === "/auth/managed-rendezvous/failover/import" && method === "POST") {
      return json(route, {
        status: "imported",
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        target_node_id: "node-beta",
        public_url: "https://node-beta.local/rendezvous",
        restart_required: true,
        cert_path: "tls/rendezvous.pem",
        key_path: "tls/rendezvous.key"
      });
    }

    if (pathname === "/auth/managed-control-plane/promotion/import" && method === "POST") {
      return json(route, {
        status: "imported",
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        target_node_id: "node-beta",
        public_url: "https://node-beta.local/rendezvous",
        restart_required: true,
        signer_ca_cert_path: "tls/cluster-ca.pem",
        rendezvous_cert_path: "tls/rendezvous.pem",
        rendezvous_key_path: "tls/rendezvous.key"
      });
    }

    return route.continue();
  });
}

function buildCredentialList(revokedDeviceIds: Set<string>) {
  return [
    {
      device_id: "client-credential-a",
      label: "Pixel test phone",
      public_key_fingerprint: "pk-client-credential-a",
      credential_fingerprint: "cred-client-credential-a",
      created_at_unix: 1_900_000_001,
      revocation_reason: revokedDeviceIds.has("client-credential-a") ? "manual smoke revocation" : null,
      revoked_by_actor: revokedDeviceIds.has("client-credential-a") ? "admin" : null,
      revoked_by_source_node: revokedDeviceIds.has("client-credential-a") ? "node-alpha" : null,
      revoked_at_unix: revokedDeviceIds.has("client-credential-a") ? 1_900_000_100 : null
    },
    {
      device_id: "client-credential-b",
      label: "Desktop sync client",
      public_key_fingerprint: "pk-client-credential-b",
      credential_fingerprint: "cred-client-credential-b",
      created_at_unix: 1_900_000_002,
      revocation_reason: null,
      revoked_by_actor: null,
      revoked_by_source_node: null,
      revoked_at_unix: null
    }
  ];
}

async function json(route: Route, payload: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(payload)
  });
}

function tinyPngBuffer(): Buffer {
  return Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0N8AAAAASUVORK5CYII=",
    "base64"
  );
}
