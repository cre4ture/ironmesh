async function refreshSetupStatus() {
  const output = document.getElementById('setup-status-json');
  try {
    const response = await fetch('/setup/status', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('HTTP ' + response.status);
    }
    const payload = await response.json();
    output.textContent = JSON.stringify(payload, null, 2);
  } catch (error) {
    output.textContent = 'failed to load setup status: ' + error;
  }
}

function saveBootstrapAdminToken(token) {
  if (!token) {
    return;
  }
  try {
    sessionStorage.setItem('ironmeshAdminToken', token);
  } catch {
    // Ignore sessionStorage failures and let the operator re-enter the token after transition.
  }
}

async function waitForRuntimeTransition() {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    try {
      const response = await fetch('/', { cache: 'no-store' });
      if (!response.ok) {
        continue;
      }
      const html = await response.text();
      if (!html.includes('ironmesh First-Run Setup')) {
        window.location.href = '/';
        return;
      }
    } catch {
      // The server may still be switching modes.
    }
  }
  window.location.href = '/';
}

async function startNewCluster() {
  const output = document.getElementById('setup-start-output');
  const adminPassword = document.getElementById('setup-start-admin-password').value.trim();
  if (!adminPassword) {
    output.textContent = 'admin password is required';
    return;
  }

  output.textContent = 'creating cluster and switching runtime...';
  try {
    const response = await fetch('/setup/start-cluster', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        admin_password: adminPassword,
        public_origin: window.location.origin
      })
    });

    const payload = await response.json().catch(() => ({ status: response.status }));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    saveBootstrapAdminToken(adminPassword);
    output.textContent = JSON.stringify(payload, null, 2) + '\n\ntransitioning to normal runtime...';
    await waitForRuntimeTransition();
  } catch (error) {
    output.textContent = 'failed to start cluster: ' + error;
  }
}

async function generateJoinRequest() {
  const output = document.getElementById('setup-join-request-output');
  output.textContent = 'generating join request...';
  try {
    const response = await fetch('/setup/join/request', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        public_origin: window.location.origin
      })
    });

    const payload = await response.json().catch(() => ({ status: response.status }));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    output.textContent = JSON.stringify(payload, null, 2);
    await refreshSetupStatus();
  } catch (error) {
    output.textContent = 'failed to generate join request: ' + error;
  }
}

async function importEnrollmentPackage() {
  const output = document.getElementById('setup-import-output');
  const adminPassword = document.getElementById('setup-join-admin-password').value.trim();
  const packageJson = document.getElementById('setup-enrollment-json').value.trim();

  if (!adminPassword) {
    output.textContent = 'cluster admin password is required';
    return;
  }
  if (!packageJson) {
    output.textContent = 'node enrollment package JSON is required';
    return;
  }

  output.textContent = 'importing node enrollment package and switching runtime...';
  try {
    const response = await fetch('/setup/join/import', {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        admin_password: adminPassword,
        package_json: packageJson
      })
    });

    const payload = await response.json().catch(() => ({ status: response.status }));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`);
    }

    saveBootstrapAdminToken(adminPassword);
    output.textContent = JSON.stringify(payload, null, 2) + '\n\ntransitioning to normal runtime...';
    await waitForRuntimeTransition();
  } catch (error) {
    output.textContent = 'failed to import node enrollment package: ' + error;
  }
}

document
  .getElementById('setup-start-cluster')
  .addEventListener('click', startNewCluster);

document
  .getElementById('setup-generate-join-request')
  .addEventListener('click', generateJoinRequest);

document
  .getElementById('setup-import-enrollment')
  .addEventListener('click', importEnrollmentPackage);

refreshSetupStatus();
