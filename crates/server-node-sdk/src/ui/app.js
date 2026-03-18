async function refreshServerLogs() {
  try {
    const response = await fetch('/logs?limit=200', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('HTTP ' + response.status);
    }

    const payload = await response.json();
    const logs = Array.isArray(payload.entries) ? payload.entries : [];
    document.getElementById('server-logs').textContent = logs.join('\n') || 'no logs yet';
  } catch (error) {
    document.getElementById('server-logs').textContent = 'failed to load logs: ' + error;
  }
}

function prefillAdminTokenFromSession() {
  let stored = '';
  try {
    stored = sessionStorage.getItem('ironmeshAdminToken') || '';
  } catch {
    stored = '';
  }
  if (!stored) {
    return;
  }

  ['bootstrap-admin-token', 'node-bootstrap-admin-token'].forEach((id) => {
    const input = document.getElementById(id);
    if (input && !input.value) {
      input.value = stored;
    }
  });
}

async function fetchReplicationPlan() {
  const output = document.getElementById('replication-plan-json');
  output.textContent = 'loading...';
  try {
    const response = await fetch('/cluster/replication/plan', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('HTTP ' + response.status);
    }
    const payload = await response.json();
    output.textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    output.textContent = 'failed to load replication plan: ' + error;
  }
}

async function triggerReplicationRepair() {
  const output = document.getElementById('replication-repair-json');
  output.textContent = 'triggering repair...';
  try {
    const response = await fetch('/cluster/replication/repair', {
      method: 'POST',
      cache: 'no-store'
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    output.textContent = 'failed to trigger replication repair: ' + error;
  }
}

async function issueBootstrapBundle() {
  const output = document.getElementById('bootstrap-bundle-json');
  const notes = document.getElementById('bootstrap-bundle-notes');
  const qrStatus = document.getElementById('bootstrap-bundle-qr-status');
  const adminToken = document.getElementById('bootstrap-admin-token').value.trim();
  const deviceLabel = document.getElementById('bootstrap-device-label').value.trim();
  const expiryRaw = document.getElementById('bootstrap-expiry-secs').value.trim();

  if (!adminToken) {
    output.textContent = 'admin token is required';
    notes.textContent = '';
    return;
  }

  let expiresInSecs = Number.parseInt(expiryRaw, 10);
  if (!Number.isFinite(expiresInSecs)) {
    expiresInSecs = 3600;
  }

  hideBootstrapQr();
  notes.textContent = '';
  qrStatus.textContent = '';
  output.textContent = 'issuing bootstrap bundle...';
  try {
    const response = await fetch('/auth/bootstrap-bundles/issue', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json',
        'x-ironmesh-admin-token': adminToken
      },
      body: JSON.stringify({
        label: deviceLabel || null,
        expires_in_secs: expiresInSecs
      })
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    const bundleText = JSON.stringify(payload, null, 2);
    output.textContent = bundleText;
    notes.textContent = summarizeBootstrapBundle(payload);
    const qrError = renderBootstrapQr(JSON.stringify(payload));
    if (qrError) {
      qrStatus.textContent = qrError;
    }
  } catch (error) {
    output.textContent = 'failed to issue bootstrap bundle: ' + error;
    notes.textContent = '';
    qrStatus.textContent = '';
    hideBootstrapQr();
  }
}

async function issueNodeBootstrap() {
  const output = document.getElementById('node-bootstrap-json');
  const notes = document.getElementById('node-bootstrap-notes');
  const adminToken = document.getElementById('node-bootstrap-admin-token').value.trim();
  if (!adminToken) {
    output.textContent = 'admin token is required';
    notes.textContent = '';
    return;
  }

  const body = buildNodeBootstrapRequest();
  output.textContent = 'issuing node bootstrap...';
  notes.textContent = '';
  try {
    const response = await fetch('/auth/node-bootstraps/issue', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json',
        'x-ironmesh-admin-token': adminToken
      },
      body: JSON.stringify(body)
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
    notes.textContent = summarizeNodeBootstrap(payload);
  } catch (error) {
    output.textContent = 'failed to issue node bootstrap: ' + error;
    notes.textContent = '';
  }
}

function parseOptionalPositiveInt(value, fallback = null) {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function readNodeTlsPolicy() {
  return {
    tls_validity_secs: parseOptionalPositiveInt(
      document.getElementById('node-bootstrap-tls-validity-secs').value.trim(),
      null
    ),
    tls_renewal_window_secs: parseOptionalPositiveInt(
      document.getElementById('node-bootstrap-tls-renewal-window-secs').value.trim(),
      null
    )
  };
}

function buildNodeBootstrapRequest() {
  const mode = document.getElementById('node-bootstrap-mode').value;
  const bindAddr = document.getElementById('node-bootstrap-bind-addr').value.trim();
  const publicTlsCert = document.getElementById('node-bootstrap-public-tls-cert').value.trim();
  const publicTlsKey = document.getElementById('node-bootstrap-public-tls-key').value.trim();
  const internalTlsCa = document.getElementById('node-bootstrap-internal-tls-ca').value.trim();
  const internalTlsCert = document.getElementById('node-bootstrap-internal-tls-cert').value.trim();
  const internalTlsKey = document.getElementById('node-bootstrap-internal-tls-key').value.trim();
  const body = {
    node_id: document.getElementById('node-bootstrap-node-id').value.trim() || null,
    mode,
    data_dir: document.getElementById('node-bootstrap-data-dir').value.trim() || null,
    bind_addr: bindAddr || null,
    public_url: document.getElementById('node-bootstrap-public-url').value.trim() || null,
    public_ca_cert_path: document.getElementById('node-bootstrap-public-ca-cert').value.trim() || null,
    public_peer_api_enabled: document.getElementById('node-bootstrap-public-peer-api-enabled').checked,
    internal_bind_addr: document.getElementById('node-bootstrap-internal-bind-addr').value.trim() || null,
    internal_url: document.getElementById('node-bootstrap-internal-url').value.trim() || null,
    ...readNodeTlsPolicy()
  };

  if (publicTlsCert && publicTlsKey) {
    body.public_tls = {
      cert_path: publicTlsCert,
      key_path: publicTlsKey
    };
  }

  if (mode === 'cluster' || internalTlsCa || internalTlsCert || internalTlsKey) {
    body.internal_tls = {
      ca_cert_path: internalTlsCa,
      cert_path: internalTlsCert,
      key_path: internalTlsKey
    };
  }

  return body;
}

async function issueNodeEnrollment() {
  const output = document.getElementById('node-enrollment-json');
  const notes = document.getElementById('node-enrollment-notes');
  const adminToken = document.getElementById('node-bootstrap-admin-token').value.trim();
  if (!adminToken) {
    output.textContent = 'admin token is required';
    notes.textContent = '';
    return;
  }

  output.textContent = 'issuing node enrollment package...';
  notes.textContent = '';
  try {
    const response = await fetch('/auth/node-enrollments/issue', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json',
        'x-ironmesh-admin-token': adminToken
      },
      body: JSON.stringify(buildNodeBootstrapRequest())
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
    notes.textContent = summarizeNodeEnrollment(payload);
  } catch (error) {
    output.textContent = 'failed to issue node enrollment package: ' + error;
    notes.textContent = '';
  }
}

async function renewNodeEnrollment() {
  const output = document.getElementById('node-renewal-json');
  const notes = document.getElementById('node-renewal-notes');
  const adminToken = document.getElementById('node-bootstrap-admin-token').value.trim();
  const packageRaw = document.getElementById('node-renewal-package-json').value.trim();
  if (!adminToken) {
    output.textContent = 'admin token is required';
    notes.textContent = '';
    return;
  }
  if (!packageRaw) {
    output.textContent = 'existing node enrollment JSON is required';
    notes.textContent = '';
    return;
  }

  let parsedPackage;
  try {
    parsedPackage = JSON.parse(packageRaw);
  } catch (error) {
    output.textContent = 'failed to parse existing node enrollment JSON: ' + error;
    notes.textContent = '';
    return;
  }

  output.textContent = 'renewing node enrollment package...';
  notes.textContent = '';
  try {
    const response = await fetch('/auth/node-enrollments/renew', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json',
        'x-ironmesh-admin-token': adminToken
      },
      body: JSON.stringify({
        package: parsedPackage,
        ...readNodeTlsPolicy()
      })
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
    notes.textContent = summarizeNodeEnrollment(payload);
  } catch (error) {
    output.textContent = 'failed to renew node enrollment package: ' + error;
    notes.textContent = '';
  }
}

async function fetchNodeCertificateStatus() {
  const output = document.getElementById('node-certificate-status-json');
  const notes = document.getElementById('node-certificate-status-notes');
  const adminToken = document.getElementById('node-bootstrap-admin-token').value.trim();
  if (!adminToken) {
    output.textContent = 'admin token is required';
    notes.textContent = '';
    return;
  }

  output.textContent = 'loading...';
  notes.textContent = '';
  try {
    const response = await fetch('/auth/node-certificates/status', {
      method: 'GET',
      cache: 'no-store',
      headers: {
        'x-ironmesh-admin-token': adminToken
      }
    });

    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { status: response.status, message: 'no JSON body returned' };
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
    notes.textContent = summarizeNodeCertificateStatus(payload);
  } catch (error) {
    output.textContent = 'failed to fetch node certificate status: ' + error;
    notes.textContent = '';
  }
}

function formatUnixTs(unixTs) {
  const parsed = Number(unixTs);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 'unknown';
  }
  return new Date(parsed * 1000).toISOString();
}

function summarizeTlsMaterial(label, material) {
  if (!material?.metadata) {
    return `${label}: no issued metadata`;
  }
  return `${label}: renew after ${formatUnixTs(material.metadata.renew_after_unix)}, expires ${formatUnixTs(material.metadata.not_after_unix)}`;
}

function summarizeBootstrapBundle(payload) {
  const rendezvousUrls = Array.isArray(payload.rendezvous_urls) ? payload.rendezvous_urls.length : 0;
  const directEndpoints = Array.isArray(payload.direct_endpoints) ? payload.direct_endpoints.length : 0;
  const trustRoots = payload && typeof payload === 'object' ? payload.trust_roots || {} : {};
  const notes = [
    `rendezvous URLs: ${rendezvousUrls}`,
    `direct endpoints: ${directEndpoints}`,
    `relay mode: ${payload?.relay_mode || 'unknown'}`,
    `rendezvous mTLS required: ${payload?.rendezvous_mtls_required ? 'yes' : 'no'}`
  ];

  if (trustRoots.rendezvous_ca_pem) {
    notes.push('includes rendezvous CA trust root');
  }
  if (trustRoots.public_api_ca_pem) {
    notes.push('includes public API CA trust root');
  }
  if (trustRoots.cluster_ca_pem) {
    notes.push('includes cluster CA trust root');
  }

  return notes.join(' | ');
}

function summarizeNodeBootstrap(payload) {
  const directEndpoints = Array.isArray(payload.direct_endpoints) ? payload.direct_endpoints.length : 0;
  const trustRoots = payload && typeof payload === 'object' ? payload.trust_roots || {} : {};
  const notes = [
    `mode: ${payload?.mode || 'unknown'}`,
    `rendezvous URLs: ${Array.isArray(payload?.rendezvous_urls) ? payload.rendezvous_urls.length : 0}`,
    `direct endpoints: ${directEndpoints}`,
    `relay mode: ${payload?.relay_mode || 'unknown'}`,
    `rendezvous mTLS required: ${payload?.rendezvous_mtls_required ? 'yes' : 'no'}`
  ];

  if (payload?.internal_tls) {
    notes.push('includes internal TLS file paths');
  }
  if (payload?.public_tls) {
    notes.push('includes public TLS file paths');
  }
  if (payload?.enrollment_issuer_url) {
    notes.push(`enrollment issuer: ${payload.enrollment_issuer_url}`);
  }
  if (trustRoots.rendezvous_ca_pem) {
    notes.push('includes rendezvous CA trust root');
  }
  if (trustRoots.cluster_ca_pem) {
    notes.push('includes cluster CA trust root');
  }

  return notes.join(' | ');
}

function summarizeNodeEnrollment(payload) {
  const notes = [];
  if (payload?.bootstrap) {
    notes.push(summarizeNodeBootstrap(payload.bootstrap));
  }
  if (payload?.public_tls_material?.cert_pem) {
    notes.push('includes generated public HTTPS certificate');
  }
  if (payload?.public_tls_material?.key_pem) {
    notes.push('includes generated public HTTPS private key');
  }
  if (payload?.public_tls_material?.ca_cert_pem) {
    notes.push('includes public API CA certificate');
  }
  if (payload?.public_tls_material?.metadata) {
    notes.push(summarizeTlsMaterial('public TLS', payload.public_tls_material));
  }
  if (payload?.internal_tls_material?.cert_pem) {
    notes.push('includes generated internal node certificate');
  }
  if (payload?.internal_tls_material?.key_pem) {
    notes.push('includes generated internal node private key');
  }
  if (payload?.internal_tls_material?.ca_cert_pem) {
    notes.push('includes cluster CA certificate');
  }
  if (payload?.internal_tls_material?.metadata) {
    notes.push(summarizeTlsMaterial('internal TLS', payload.internal_tls_material));
  }

  return notes.join(' | ');
}

function summarizeNodeCertificateStatus(payload) {
  const entries = [payload?.public_tls, payload?.internal_tls].filter(Boolean);
  const notes = entries
    .map((entry) => {
      let note = `${entry.name}: ${entry.state}`;
      if (entry.expires_at_unix) {
        note += `, expires ${formatUnixTs(entry.expires_at_unix)}`;
      }
      if (entry.renew_after_unix) {
        note += `, renew after ${formatUnixTs(entry.renew_after_unix)}`;
      }
      if (entry.metadata_matches_certificate === false) {
        note += ', metadata fingerprint mismatch';
      }
      return note;
    })
    .filter(Boolean);

  if (payload?.auto_renew) {
    let autoRenew = `auto renew: ${payload.auto_renew.enabled ? 'enabled' : 'disabled'}`;
    if (payload.auto_renew.issuer_url) {
      autoRenew += ` via ${payload.auto_renew.issuer_url}`;
    }
    if (payload.auto_renew.restart_required) {
      autoRenew += ', restart required';
    } else if (payload.auto_renew.last_success_unix) {
      autoRenew += ', live reload applied';
    }
    if (payload.auto_renew.last_error) {
      autoRenew += `, last error: ${payload.auto_renew.last_error}`;
    }
    notes.push(autoRenew);
  }

  return notes.join(' | ');
}

function renderBootstrapQr(text) {
  const container = document.getElementById('bootstrap-bundle-qr-container');
  const target = document.getElementById('bootstrap-bundle-qr');
  if (typeof QRCode === 'undefined') {
    container.style.display = 'none';
    return 'QR library did not load';
  }
  target.innerHTML = '';
  try {
    new QRCode(target, {
      text,
      width: 320,
      height: 320,
      correctLevel: QRCode.CorrectLevel.L
    });
    container.style.display = 'block';
    return '';
  } catch {
    container.style.display = 'none';
    return 'Bootstrap bundle is too large for a single QR code';
  }
}

function hideBootstrapQr() {
  document.getElementById('bootstrap-bundle-qr-container').style.display = 'none';
  document.getElementById('bootstrap-bundle-qr').innerHTML = '';
  document.getElementById('bootstrap-bundle-qr-status').textContent = '';
}

document
  .getElementById('fetch-replication-plan')
  .addEventListener('click', fetchReplicationPlan);

document
  .getElementById('trigger-replication-repair')
  .addEventListener('click', triggerReplicationRepair);

document
  .getElementById('issue-bootstrap-bundle')
  .addEventListener('click', issueBootstrapBundle);

document
  .getElementById('issue-node-bootstrap')
  .addEventListener('click', issueNodeBootstrap);

document
  .getElementById('issue-node-enrollment')
  .addEventListener('click', issueNodeEnrollment);

document
  .getElementById('renew-node-enrollment')
  .addEventListener('click', renewNodeEnrollment);

document
  .getElementById('fetch-node-certificate-status')
  .addEventListener('click', fetchNodeCertificateStatus);

prefillAdminTokenFromSession();
refreshServerLogs();
setInterval(refreshServerLogs, 2000);
