pub fn app_html() -> String {
    r#"<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>ironmesh Client</title>
    <style>
                body { font-family: system-ui, sans-serif; margin: 1.5rem; background: #fafafa; }
                main { max-width: 960px; margin: 0 auto; }
                section { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
                h1, h2 { margin-top: 0; }
                label { display: block; margin: 0.4rem 0 0.2rem; font-weight: 600; }
                input, textarea, button { font: inherit; }
                input, textarea { width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
                textarea { min-height: 110px; }
                .row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
                .actions { margin-top: 0.6rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
                button { padding: 0.5rem 0.8rem; border: 1px solid #888; border-radius: 6px; background: #f5f5f5; cursor: pointer; }
                pre { background: #111; color: #f2f2f2; padding: 0.8rem; border-radius: 6px; overflow: auto; }
                .muted { color: #666; font-size: 0.92rem; }
    </style>
</head>
<body>
    <main>
        <h1>ironmesh Web UI</h1>

                <section>
                        <h2>Store: Upload / Download</h2>
                        <div class=\"row\">
                                <div>
                                        <label for=\"put-key\">Upload key</label>
                                        <input id=\"put-key\" placeholder=\"docs/readme.txt\" />
                                        <label for=\"put-value\">Upload value</label>
                                        <textarea id=\"put-value\" placeholder=\"content\"></textarea>
                                        <div class=\"actions\"><button onclick=\"uploadObject()\">Upload</button></div>
                                </div>
                                <div>
                                        <label for=\"get-key\">Download key</label>
                                        <input id=\"get-key\" placeholder=\"docs/readme.txt\" />
                                        <div class=\"actions\"><button onclick=\"downloadObject()\">Download</button></div>
                                        <label for=\"get-value\">Downloaded value</label>
                                        <textarea id=\"get-value\" readonly></textarea>
                                </div>
                        </div>
                </section>

                <section>
                        <h2>Store: Browse by Prefix / Depth</h2>
                        <p class=\"muted\">Use slash-separated keys as virtual directories.</p>
                        <div class=\"row\">
                                <div>
                                        <label for=\"list-prefix\">Prefix</label>
                                        <input id=\"list-prefix\" placeholder=\"docs\" />
                                </div>
                                <div>
                                        <label for=\"list-depth\">Depth</label>
                                        <input id=\"list-depth\" type=\"number\" min=\"1\" value=\"1\" />
                                </div>
                        </div>
                        <div class=\"actions\"><button onclick=\"listKeys()\">List Keys</button></div>
                        <pre id=\"list-output\">(no data yet)</pre>
                </section>

                <section>
                        <h2>Cluster Health and Replication</h2>
                        <div class=\"actions\">
                                <button onclick=\"fetchHealth()\">Health</button>
                                <button onclick=\"fetchClusterStatus()\">Cluster Status</button>
                                <button onclick=\"fetchNodes()\">Nodes</button>
                                <button onclick=\"fetchReplicationPlan()\">Replication Plan</button>
                        </div>
                        <pre id=\"status-output\">(no data yet)</pre>
                </section>
    </main>

        <script>
            async function fetchJson(url, options) {
                const response = await fetch(url, options);
                const payload = await response.json();
                if (!response.ok) {
                    throw new Error(payload.error || JSON.stringify(payload));
                }
                return payload;
            }

            function show(id, value) {
                document.getElementById(id).textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
            }

            async function uploadObject() {
                const key = document.getElementById('put-key').value;
                const value = document.getElementById('put-value').value;
                try {
                    const payload = await fetchJson('/api/store/put', {
                        method: 'POST',
                        headers: { 'content-type': 'application/json' },
                        body: JSON.stringify({ key, value })
                    });
                    show('status-output', payload);
                } catch (err) {
                    show('status-output', { error: err.message });
                }
            }

            async function downloadObject() {
                const key = document.getElementById('get-key').value;
                try {
                    const payload = await fetchJson('/api/store/get?key=' + encodeURIComponent(key));
                    document.getElementById('get-value').value = payload.value || '';
                    show('status-output', payload);
                } catch (err) {
                    show('status-output', { error: err.message });
                }
            }

            async function listKeys() {
                const prefix = document.getElementById('list-prefix').value;
                const depth = document.getElementById('list-depth').value || '1';
                const query = new URLSearchParams({ depth });
                if (prefix) query.set('prefix', prefix);
                try {
                    const payload = await fetchJson('/api/store/list?' + query.toString());
                    show('list-output', payload);
                } catch (err) {
                    show('list-output', { error: err.message });
                }
            }

            async function fetchHealth() {
                try { show('status-output', await fetchJson('/api/health')); }
                catch (err) { show('status-output', { error: err.message }); }
            }
            async function fetchClusterStatus() {
                try { show('status-output', await fetchJson('/api/cluster/status')); }
                catch (err) { show('status-output', { error: err.message }); }
            }
            async function fetchNodes() {
                try { show('status-output', await fetchJson('/api/cluster/nodes')); }
                catch (err) { show('status-output', { error: err.message }); }
            }
            async function fetchReplicationPlan() {
                try { show('status-output', await fetchJson('/api/cluster/replication/plan')); }
                catch (err) { show('status-output', { error: err.message }); }
            }
        </script>
</body>
</html>
"#
        .to_string()
}
