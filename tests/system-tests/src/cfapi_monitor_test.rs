#![cfg(windows)]

#[cfg(test)]
mod tests {
    use crate::framework::{fresh_data_dir, start_server};
    use crate::framework_win::start_cfapi_adapter;
    use reqwest::Client;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;

    async fn run_cfapi_monitor_case(bind: &str, initial_content: &str, modified_content: &str) {
        let _server = start_server(bind)
            .await
            .expect("Failed to start local server-node");

        let base_url = format!("http://{bind}");
        let sync_root = fresh_data_dir("cfapi-monitor-sync-root-parameterized");
        std::fs::create_dir_all(&sync_root).expect("Failed to create sync root");

        let test_file = sync_root.join("monitor_test.txt");
        let server_url = format!("{}/store/monitor_test.txt", base_url);
        let client = Client::new();

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        file.write_all(initial_content.as_bytes())
            .expect("Failed to write initial content");
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
            body.contains(initial_content),
            "Initial content not found on server"
        );

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        file.write_all(modified_content.as_bytes())
            .expect("Failed to write modified content");
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
            body.contains(modified_content),
            "Modified content not found on server"
        );
    }

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file_small() {
        run_cfapi_monitor_case("127.0.0.1:19090", "initial content", "modified content").await;
    }

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file_large() {
        let large_initial = format!("{}{}", "A".repeat(5 * 1024 * 1024 + 1024), "\ninitial-tail");
        let large_modified = format!(
            "{}{}",
            "B".repeat(5 * 1024 * 1024 + 1024),
            "\nmodified-tail"
        );

        run_cfapi_monitor_case("127.0.0.1:19091", &large_initial, &large_modified).await;
    }
}
