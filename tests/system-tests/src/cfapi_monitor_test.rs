#[cfg(test)]
mod cfapi_monitor_test {
    use std::fs::{self, File};
    use std::io::Write;
    use std::thread;
    use std::time::Duration;
    use reqwest::blocking::Client;
    use crate::{start_server, stop_server};

    #[test]
    fn test_cfapi_monitor_detects_new_and_modified_file() {
        let bind = "127.0.0.1:19090";
        let mut server = start_server(bind).expect("Failed to start local server-node");
        let base_url = format!("http://{bind}");
        let sync_root = "C:/ironmesh-sync2";
        let test_file = format!("{}/monitor_test.txt", sync_root);
        let server_url = format!("{}/store/monitor_test.txt", base_url);
        let client = Client::new();

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        writeln!(file, "initial content").expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

        // Wait for monitor to detect and upload
        thread::sleep(Duration::from_secs(10));
        let resp = client.get(&server_url).send().expect("Failed to GET file");
        let body = resp.text().expect("Failed to read response body");
        assert!(body.contains("initial content"), "Initial content not found on server");

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        writeln!(file, "modified content").expect("Failed to write modified content");
        file.sync_all().expect("Failed to sync file");

        // Wait for monitor to detect and upload
        thread::sleep(Duration::from_secs(10));
        let resp = client.get(&server_url).send().expect("Failed to GET file after modification");
        let body = resp.text().expect("Failed to read response body");
        assert!(body.contains("modified content"), "Modified content not found on server");

        stop_server(&mut server).expect("Failed to stop local server-node");
    }
}
