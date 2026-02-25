let currentExplorer = null;

    async function fetchJson(url, options) {
      const response = await fetch(url, options);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || JSON.stringify(payload));
      }
      return payload;
    }

    function show(id, value) {
      document.getElementById(id).textContent =
        typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    }

    function normalizePath(path) {
      return (path || '')
        .split('/')
        .map(segment => segment.trim())
        .filter(Boolean)
        .join('/');
    }

    function parentPath(path) {
      const parts = normalizePath(path).split('/').filter(Boolean);
      parts.pop();
      return parts.join('/');
    }

    function folderMarkerKey(path) {
      const normalized = normalizePath(path);
      return normalized ? normalized + '/' : '';
    }

    function joinPath(basePath, childPath) {
      const base = normalizePath(basePath);
      const child = normalizePath(childPath);
      if (!base) return child;
      if (!child) return base;
      return base + '/' + child;
    }

    async function refreshCurrentExplorer() {
      if (currentExplorer && typeof currentExplorer.refresh === 'function') {
        await currentExplorer.refresh();
      }
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
        await refreshCurrentExplorer();
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

    async function uploadBinaryFile() {
      const keyInput = document.getElementById('binary-upload-key');
      const fileInput = document.getElementById('binary-upload-file');
      const file = fileInput.files && fileInput.files[0];

      if (!file) {
        show('status-output', { error: 'Please select a file to upload.' });
        return;
      }

      const key = (keyInput.value || file.name || '').trim();
      if (!key) {
        show('status-output', { error: 'Upload key must not be empty.' });
        return;
      }

      try {
        const response = await fetch('/api/store/put-binary?key=' + encodeURIComponent(key), {
          method: 'POST',
          body: file,
          headers: {
            'content-type': file.type || 'application/octet-stream'
          }
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || JSON.stringify(payload));
        }
        keyInput.value = key;
        show('status-output', {
          ...payload,
          uploaded_filename: file.name,
          uploaded_type: file.type || 'application/octet-stream'
        });
        await refreshCurrentExplorer();
      } catch (err) {
        show('status-output', { error: err.message });
      }
    }

    async function downloadBinaryFile() {
      const key = document.getElementById('binary-download-key').value.trim();
      const preferredName = document.getElementById('binary-download-name').value.trim();
      if (!key) {
        show('status-output', { error: 'Download key must not be empty.' });
        return;
      }

      try {
        const response = await fetch('/api/store/get-binary?key=' + encodeURIComponent(key));
        if (!response.ok) {
          let errorPayload;
          try {
            errorPayload = await response.json();
          } catch {
            errorPayload = { error: 'HTTP ' + response.status };
          }
          throw new Error(errorPayload.error || JSON.stringify(errorPayload));
        }

        const blob = await response.blob();
        let filename = preferredName;
        if (!filename) {
          const disposition = response.headers.get('content-disposition') || '';
          const match = disposition.match(/filename="([^"]+)"/i);
          filename = (match && match[1]) || key.split('/').pop() || 'download.bin';
        }

        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = objectUrl;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(objectUrl);

        show('status-output', {
          key,
          saved_as: filename,
          size_bytes: blob.size,
          type: blob.type || 'application/octet-stream'
        });
      } catch (err) {
        show('status-output', { error: err.message });
      }
    }

    async function createFolderMarker(path) {
      const markerKey = folderMarkerKey(path);
      if (!markerKey) {
        throw new Error('Folder path must not be empty.');
      }

      return fetchJson('/api/store/put', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: markerKey, value: '' }),
      });
    }

    async function deleteObjectKey(key) {
      const query = new URLSearchParams({ key });
      return fetchJson('/api/store/delete?' + query.toString(), { method: 'DELETE' });
    }

    async function deleteFolderMarker(path) {
      const markerKey = folderMarkerKey(path);
      if (!markerKey) {
        throw new Error('Cannot delete root folder.');
      }
      return deleteObjectKey(markerKey);
    }

    async function listStoreEntries(prefix, snapshot) {
      const query = new URLSearchParams({ depth: '1' });
      const normalizedPrefix = normalizePath(prefix);
      if (normalizedPrefix) query.set('prefix', folderMarkerKey(normalizedPrefix));
      if (snapshot) query.set('snapshot', snapshot);
      const payload = await fetchJson('/api/store/list?' + query.toString());
      return Array.isArray(payload.entries) ? payload.entries : [];
    }

    function childEntriesForPath(entries, path) {
      const normalizedPath = normalizePath(path);
      const basePrefix = normalizedPath ? normalizedPath + '/' : '';

      return entries
        .filter(entry => {
          const target = String(entry.path || '');
          if (!target) return false;
          if (!basePrefix) return true;
          return target.startsWith(basePrefix) && target !== basePrefix;
        })
        .map(entry => {
          const rawPath = String(entry.path || '');
          const stripped = basePrefix ? rawPath.slice(basePrefix.length) : rawPath;
          const withoutTrailing = stripped.replace(/\/$/, '');
          const label = withoutTrailing.includes('/') ? withoutTrailing.split('/')[0] : withoutTrailing;
          const isDir = entry.entry_type === 'prefix' || rawPath.endsWith('/');
          const itemPath = joinPath(normalizedPath, label);
          return {
            label,
            fullPath: isDir ? folderMarkerKey(itemPath) : itemPath,
            isDir,
          };
        })
        .filter(entry => entry.label.length > 0)
        .filter((entry, index, arr) => arr.findIndex(other => other.fullPath === entry.fullPath) === index)
        .sort((a, b) => {
          if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
          return a.label.localeCompare(b.label);
        });
    }

    function createExplorer(rootId, options) {
      const root = document.getElementById(rootId);
      let currentPath = '';

      root.innerHTML = `
        <h3>${options.title}</h3>
        ${options.controlsHtml || ''}
        <div class="explorer-path" data-path></div>
        <div class="explorer-list" data-list></div>
        <pre class="explorer-output" data-output>(select a file)</pre>
      `;

      const pathEl = root.querySelector('[data-path]');
      const listEl = root.querySelector('[data-list]');
      const outputEl = root.querySelector('[data-output]');

      function truncateExplorerPreview(value) {
        const limit = 256;
        if (typeof value === 'string') {
          return value.length > limit
            ? `${value.slice(0, limit)}... (truncated, ${value.length} chars total)`
            : value;
        }

        if (value && typeof value === 'object' && typeof value.value === 'string') {
          const original = value.value;
          if (original.length > limit) {
            return {
              ...value,
              value: `${original.slice(0, limit)}...`,
              truncated: true,
              original_length: original.length,
            };
          }
        }

        return value;
      }

      function showOutput(value) {
        const preview = truncateExplorerPreview(value);
        outputEl.textContent = typeof preview === 'string' ? preview : JSON.stringify(preview, null, 2);
      }

      const explorerApi = {
        root,
        getCurrentPath: () => currentPath,
        setCurrentPath: (path) => {
          currentPath = normalizePath(path);
        },
        refresh: render,
        showOutput,
      };

      if (typeof options.onReady === 'function') {
        options.onReady(explorerApi);
      }

      async function render() {
        pathEl.textContent = currentPath ? '/' + currentPath : '/';
        if (typeof options.onRender === 'function') {
          options.onRender(explorerApi);
        }

        listEl.innerHTML = '<div class="explorer-empty">loading...</div>';

        try {
          const entries = await options.loadEntries(currentPath, root);
          const visible = options.transformEntries
            ? options.transformEntries(entries, currentPath)
            : childEntriesForPath(entries, currentPath);

          listEl.innerHTML = '';

          if (currentPath) {
            const upBtn = document.createElement('button');
            upBtn.className = 'explorer-item';
            upBtn.textContent = '[DIR] ..';
            upBtn.onclick = () => {
              currentPath = parentPath(currentPath);
              render();
            };
            listEl.appendChild(upBtn);
          }

          if (!visible.length) {
            const empty = document.createElement('div');
            empty.className = 'explorer-empty';
            empty.textContent = '(empty)';
            listEl.appendChild(empty);
            return;
          }

          for (const entry of visible) {
            const btn = document.createElement('button');
            btn.className = 'explorer-item';
            btn.textContent = `${entry.isDir ? '[DIR]' : '[FILE]'} ${entry.label}`;
            btn.onclick = async () => {
              if (entry.isDir) {
                currentPath = normalizePath(entry.fullPath);
                render();
                return;
              }

              showOutput('loading...');
              try {
                const payload = await options.readFile(entry.fullPath, root);
                showOutput(payload);
              } catch (err) {
                showOutput({ error: err.message });
              }
            };
            listEl.appendChild(btn);
          }
        } catch (err) {
          listEl.innerHTML = '<div class="explorer-empty">(failed to load)</div>';
          showOutput({ error: err.message });
        }
      }

      root.refreshExplorer = render;
      render();
      return explorerApi;
    }

    async function fetchSnapshots() {
      const payload = await fetchJson('/api/snapshots');
      return Array.isArray(payload) ? payload : [];
    }

    async function fetchVersionsForKey(key) {
      return fetchJson('/api/versions?key=' + encodeURIComponent(key));
    }

    function wireExplorers() {
      currentExplorer = createExplorer('current-explorer', {
        title: 'Current Data',
        controlsHtml: `
          <p class="muted">Current folder: <code data-folder-path>/</code></p>
          <div class="actions">
            <button type="button" data-nav-root>Root</button>
            <button type="button" data-nav-up>Up</button>
            <button type="button" data-refresh-current>Refresh</button>
          </div>
          <label>New folder name</label>
          <input data-folder-name placeholder="new-folder" />
          <div class="actions">
            <button type="button" data-create-folder>Create Folder</button>
            <button type="button" data-delete-folder>Delete Current Folder</button>
          </div>
          <p class="muted">Delete removes only the marker key; files under the prefix are not deleted.</p>
        `,
        loadEntries: (path) => listStoreEntries(path, null),
        readFile: (fullPath) => fetchJson('/api/store/get?key=' + encodeURIComponent(fullPath)),
        onReady: (api) => {
          if (api.root.dataset.folderControlsWired) return;
          api.root.dataset.folderControlsWired = '1';

          const rootBtn = api.root.querySelector('[data-nav-root]');
          const upBtn = api.root.querySelector('[data-nav-up]');
          const refreshBtn = api.root.querySelector('[data-refresh-current]');
          const folderInput = api.root.querySelector('[data-folder-name]');
          const createBtn = api.root.querySelector('[data-create-folder]');
          const deleteBtn = api.root.querySelector('[data-delete-folder]');

          rootBtn.onclick = async () => {
            api.setCurrentPath('');
            await api.refresh();
          };

          upBtn.onclick = async () => {
            api.setCurrentPath(parentPath(api.getCurrentPath()));
            await api.refresh();
          };

          refreshBtn.onclick = async () => {
            await api.refresh();
          };

          createBtn.onclick = async () => {
            const folderName = folderInput.value.trim();
            if (!normalizePath(folderName)) {
              api.showOutput({ error: 'Folder name must not be empty.' });
              return;
            }

            const folderPath = joinPath(api.getCurrentPath(), folderName);
            const marker = folderMarkerKey(folderPath);
            api.showOutput('creating folder marker ' + marker + ' ...');

            try {
              const payload = await createFolderMarker(folderPath);
              folderInput.value = '';
              show('status-output', payload);
              await api.refresh();
              api.showOutput({ action: 'created_folder_marker', marker_key: marker });
            } catch (err) {
              api.showOutput({ error: err.message });
            }
          };

          deleteBtn.onclick = async () => {
            const folderPath = api.getCurrentPath();
            if (!folderPath) {
              api.showOutput({ error: 'Navigate into a folder before deleting.' });
              return;
            }

            const marker = folderMarkerKey(folderPath);
            api.showOutput('deleting folder marker ' + marker + ' ...');

            try {
              const payload = await deleteFolderMarker(folderPath);
              api.setCurrentPath(parentPath(folderPath));
              show('status-output', payload);
              await api.refresh();
              api.showOutput({ action: 'deleted_folder_marker', marker_key: marker });
            } catch (err) {
              api.showOutput({ error: err.message });
            }
          };
        },
        onRender: (api) => {
          const pathCode = api.root.querySelector('[data-folder-path]');
          const upBtn = api.root.querySelector('[data-nav-up]');
          const deleteBtn = api.root.querySelector('[data-delete-folder]');
          const path = api.getCurrentPath();

          if (pathCode) {
            pathCode.textContent = path ? '/' + path : '/';
          }
          if (upBtn) {
            upBtn.disabled = !path;
          }
          if (deleteBtn) {
            deleteBtn.disabled = !path;
          }
        },
      });

      createExplorer('snapshot-explorer', {
        title: 'Snapshots',
        controlsHtml: `
          <label for="snapshot-id">Snapshot ID</label>
          <select id="snapshot-id"></select>
          <p class="muted">Directory listing and reads both use selected snapshot.</p>
        `,
        loadEntries: async (path, root) => {
          const select = root.querySelector('#snapshot-id');
          if (!select.dataset.loaded) {
            const snapshots = await fetchSnapshots();
            select.innerHTML = snapshots
              .map(s => `<option value="${s.id}">${s.id}</option>`)
              .join('') || '<option value="">(no snapshots)</option>';
            select.dataset.loaded = '1';
            select.onchange = () => root.refreshExplorer();
          }
          const snapshotId = select.value;
          return listStoreEntries(path, snapshotId || null);
        },
        readFile: (fullPath, root) => {
          const snapshotId = root.querySelector('#snapshot-id').value;
          const query = new URLSearchParams({ key: fullPath });
          if (snapshotId) query.set('snapshot', snapshotId);
          return fetchJson('/api/store/get?' + query.toString());
        },
      });

      createExplorer('version-explorer', {
        title: 'Earlier Versions',
        controlsHtml: `
          <label for="version-key">Key</label>
          <input id="version-key" placeholder="docs/readme.txt" />
          <div class="actions"><button type="button" id="load-versions">Load Versions</button></div>
        `,
        loadEntries: async (_path, root) => {
          const keyInput = root.querySelector('#version-key');
          const key = keyInput.value.trim();
          const button = root.querySelector('#load-versions');
          if (!button.dataset.wired) {
            button.dataset.wired = '1';
            button.onclick = () => root.refreshExplorer();
          }
          if (!key) {
            return [];
          }

          const graph = await fetchVersionsForKey(key);
          const versions = Array.isArray(graph.versions) ? graph.versions : [];
          return versions.map(v => ({
            path: `${v.version_id}`,
            entry_type: 'key',
            meta: v,
          }));
        },
        transformEntries: (entries) => entries.map(entry => ({
          label: `${entry.path}`,
          fullPath: entry.path,
          isDir: false,
        })),
        readFile: (versionId, root) => {
          const key = root.querySelector('#version-key').value.trim();
          const query = new URLSearchParams({ key, version: versionId });
          return fetchJson('/api/store/get?' + query.toString());
        },
      });
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

    wireExplorers();
