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

  await page.getByText("Setup", { exact: true }).click();
  await expect(page.getByText("Bootstrap setup APIs are not active on this node")).toBeVisible();

  await page.getByText("Control Plane", { exact: true }).click();
  await expect(page.getByText("embedded-rendezvous.local:9443")).toBeVisible();
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

async function installServerAdminMocks(
  page: Page,
  options?: { setupMode?: boolean; bootstrapClaimMode?: "success" | "bad_gateway" }
) {
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

    if (pathname === "/logs" && method === "GET") {
      return json(route, {
        entries: [
          "2026-03-19T17:00:00Z INFO runtime ready",
          "2026-03-19T17:00:02Z INFO replication audit healthy"
        ]
      });
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
      await route.fulfill({
        status: 404,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify({ error: "setup mode not active" })
      });
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
