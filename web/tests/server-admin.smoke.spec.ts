import { expect, test, type Page, type Route } from "@playwright/test";

test("server-admin runtime smoke flow renders and navigates", async ({ page }) => {
  await installServerAdminMocks(page);

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "node-alpha", exact: true })).toBeVisible();
  await expect(page.getByText("runtime ready")).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Provisioning" })).toBeVisible();
  await page.getByRole("button", { name: "Issue bootstrap bundle" }).click();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();

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

  await page.getByText("Control Plane", { exact: true }).click();
  await page.getByRole("textbox", { name: "Target node ID" }).fill("node-beta");
  await page.getByLabel("Passphrase").first().fill("promotion-passphrase");
  await page.getByRole("button", { name: "Export promotion package" }).click();
  await expect(page.getByText("signer_backup")).toBeVisible();

  const packageJson = JSON.stringify({
    signer_backup: { version: 1, from: "node-alpha" },
    rendezvous_failover: { version: 1, to: "node-beta" }
  });
  await page.getByLabel("Promotion package JSON").fill(packageJson);
  await page.getByLabel("Passphrase").nth(1).fill("promotion-passphrase");
  await page.getByRole("button", { name: "Import promotion package" }).click();
  await expect(page.getByText("node-beta <- node-alpha")).toBeVisible();
});

async function installServerAdminMocks(page: Page) {
  let authenticated = false;
  const revokedDeviceIds = new Set<string>();

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

    if (pathname === "/logs" && method === "GET" && searchParams.get("limit") === "120") {
      return json(route, {
        entries: [
          "2026-03-19T17:00:00Z INFO runtime ready",
          "2026-03-19T17:00:02Z INFO replication audit healthy"
        ]
      });
    }

    if (pathname === "/auth/bootstrap-bundles/issue" && method === "POST") {
      return json(route, {
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
      });
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
