
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use client_sdk::ClientNode;

    use crate::framework::{start_server, stop_server};

    use anyhow::Result;


    #[tokio::test]
    async fn sdk_roundtrip_against_live_server() -> Result<()> {
        let bind = "127.0.0.1:19080";
        let base_url = format!("http://{bind}");
        let mut server = start_server(bind).await?;

        let client = ClientNode::new(&base_url);
        let key = "sdk-roundtrip";
        let value = Bytes::from_static(b"hello-from-sdk");

        client.put(key, value.clone()).await?;
        let fetched = client.get(key).await?;
        assert_eq!(fetched, value);

        stop_server(&mut server).await;
        Ok(())
    }

}