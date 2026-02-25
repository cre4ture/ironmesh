#![cfg(windows)]

#[cfg(test)]
mod cfapi_monitor_test {
    use crate::framework::{fresh_data_dir, start_cfapi_adapter, start_server};
    use reqwest::Client;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file() {
        let bind = "127.0.0.1:19090";
        let _server = start_server(bind)
            .await
            .expect("Failed to start local server-node");

        let base_url = format!("http://{bind}");
        let sync_root = fresh_data_dir("cfapi-monitor-sync-root");
        std::fs::create_dir_all(&sync_root).expect("Failed to create sync root");

        let test_file = sync_root.join("monitor_test.txt");
        let server_url = format!("{}/store/monitor_test.txt", base_url);
        let client = Client::new();

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        writeln!(file, "initial content").expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

        // start CFAPI adapter to monitor the sync root and upload changes to server
        let _adapter = start_cfapi_adapter(
            "ironmesh.systemtest.syncroot",
            "ironmesh System Test Sync Root",
            &sync_root,
            &base_url,
        )
        .await
        .expect("Failed to register and serve CFAPI adapter");

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(10)).await;
        let resp = client
            .get(&server_url)
            .send()
            .await
            .expect("Failed to GET file");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(
            body.contains("initial content"),
            "Initial content not found on server"
        );

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        writeln!(file, "modified content").expect("Failed to write modified content");
        file.sync_all().expect("Failed to sync file");
        file.flush().expect("Failed to flush file");
        drop(file); // close file to ensure changes are flushed

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(10)).await;
        let resp = client
            .get(&server_url)
            .send()
            .await
            .expect("Failed to GET file after modification");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(
            body.contains("modified content"),
            "Modified content not found on server"
        );
    }
}

