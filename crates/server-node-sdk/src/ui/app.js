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
    upstream_public_url: document.getElementById('node-bootstrap-upstream-public-url').value.trim() || null
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
  if (trustRoots.rendezvous_ca_pem) {
    notes.push('includes rendezvous CA trust root');
  }
  if (trustRoots.cluster_ca_pem) {
    notes.push('includes cluster CA trust root');
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

refreshServerLogs();
setInterval(refreshServerLogs, 2000);
