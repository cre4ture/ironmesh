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
  const adminToken = document.getElementById('bootstrap-admin-token').value.trim();
  const deviceLabel = document.getElementById('bootstrap-device-label').value.trim();
  const expiryRaw = document.getElementById('bootstrap-expiry-secs').value.trim();

  if (!adminToken) {
    output.textContent = 'admin token is required';
    return;
  }

  let expiresInSecs = Number.parseInt(expiryRaw, 10);
  if (!Number.isFinite(expiresInSecs)) {
    expiresInSecs = 3600;
  }

  hideBootstrapQr();
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
    renderBootstrapQr(JSON.stringify(payload));
  } catch (error) {
    output.textContent = 'failed to issue bootstrap bundle: ' + error;
    hideBootstrapQr();
  }
}

function renderBootstrapQr(text) {
  const container = document.getElementById('bootstrap-bundle-qr-container');
  const canvas = document.getElementById('bootstrap-bundle-qr');
  if (typeof QRCode === 'undefined') {
    container.style.display = 'none';
    return;
  }
  QRCode.toCanvas(canvas, text, { width: 320, errorCorrectionLevel: 'L' }, function (error) {
    if (error) {
      container.style.display = 'none';
    } else {
      container.style.display = 'block';
    }
  });
}

function hideBootstrapQr() {
  document.getElementById('bootstrap-bundle-qr-container').style.display = 'none';
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

refreshServerLogs();
setInterval(refreshServerLogs, 2000);
