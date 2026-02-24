#![cfg(windows)]
#[cfg(test)]
mod cfapi_monitor_test {
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use reqwest::Client;
    use crate::tests::{start_server, stop_server};

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file() {
        let bind = "127.0.0.1:19090";
        let mut server = start_server(bind).await.expect("Failed to start local server-node");
        let base_url = format!("http://{bind}");
        let sync_root = std::env::temp_dir().join("ironmesh-sync2");
        std::fs::create_dir_all(&sync_root).expect("Failed to create sync root");
        let test_file = sync_root.join("monitor_test.txt");
        let server_url = format!("{}/store/monitor_test.txt", base_url);
        let client = Client::new();

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        writeln!(file, "initial content").expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(10)).await;
        let resp = client.get(&server_url).send().await.expect("Failed to GET file");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(body.contains("initial content"), "Initial content not found on server");

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        writeln!(file, "modified content").expect("Failed to write modified content");
        file.sync_all().expect("Failed to sync file");

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(10)).await;
        let resp = client.get(&server_url).send().await.expect("Failed to GET file after modification");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(body.contains("modified content"), "Modified content not found on server");

        stop_server(&mut server).await;
    }
}
