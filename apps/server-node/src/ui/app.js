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

document
  .getElementById('fetch-replication-plan')
  .addEventListener('click', fetchReplicationPlan);

document
  .getElementById('trigger-replication-repair')
  .addEventListener('click', triggerReplicationRepair);

refreshServerLogs();
setInterval(refreshServerLogs, 2000);
