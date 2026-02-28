use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::ClientNode;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint};
use std::sync::OnceLock;

fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize android rust runtime")?;

    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .ok_or_else(|| anyhow::anyhow!("runtime initialization race"))
}

fn throw_java_error(env: &mut JNIEnv, message: impl AsRef<str>) {
    let _ = env.throw_new("java/lang/RuntimeException", message.as_ref());
}

pub struct AndroidStorageApp {
    client: ClientNode,
}

impl AndroidStorageApp {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            client: ClientNode::new(server_base_url),
        }
    }

    pub async fn store(&self, key: impl Into<String>, data: Vec<u8>) -> Result<()> {
        self.client.put(key, Bytes::from(data)).await?;
        Ok(())
    }

    pub async fn fetch(&self, key: impl AsRef<str>) -> Result<Vec<u8>> {
        let bytes = self.client.get_cached_or_fetch(key).await?;
        Ok(bytes.to_vec())
    }

    pub fn web_gui_html(&self) -> String {
        web_ui::app_html()
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_putObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
    payload: jbyteArray,
) -> jint {
    let result = (|| -> Result<jint> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let payload_ref = unsafe { JByteArray::from_raw(payload) };
        let payload = env.convert_byte_array(&payload_ref)?;

        let rt = runtime()?;
        let client = ClientNode::new(base_url);
        let report = rt.block_on(client.put_large_aware(key, Bytes::from(payload)))?;
        Ok(report.meta.size_bytes as jint)
    })();

    match result {
        Ok(size) => size,
        Err(err) => {
            throw_java_error(&mut env, format!("rust putObject failed: {err:#}"));
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_getObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let rt = runtime()?;
        let client = ClientNode::new(base_url);
        let mut bytes = rt.block_on(client.get(key))?.to_vec();
        bytes.push(b'R');
        bytes.push(b'u');
        bytes.push(b's');
        bytes.push(b't');
        Ok([b"Rust".to_vec(), bytes].concat())
    })();

    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust getObject failed to create byte[]: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust getObject failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}
