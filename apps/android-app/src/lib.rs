use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::{
    ClientNode, DeviceEnrollmentRequest, IronMeshClient, build_http_client, enroll_device,
};
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jbyte, jbyteArray, jint, jstring};
use std::io::{Read, Write};
use std::sync::{Mutex, OnceLock};
use tokio::task::JoinHandle;

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

struct WebUiServer {
    base_url: String,
    local_url: String,
    task: JoinHandle<()>,
}

fn web_ui_server_state() -> &'static Mutex<Option<WebUiServer>> {
    static STATE: OnceLock<Mutex<Option<WebUiServer>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn start_embedded_web_ui(base_url: String) -> Result<String> {
    let rt = runtime()?;
    let mut state = web_ui_server_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("web ui state lock poisoned"))?;

    if let Some(existing) = state.as_ref()
        && existing.base_url == base_url
        && !existing.task.is_finished()
    {
        return Ok(existing.local_url.clone());
    }

    if let Some(previous) = state.take() {
        previous.task.abort();
    }

    let listener = rt
        .block_on(async { tokio::net::TcpListener::bind(("127.0.0.1", 0)).await })
        .context("failed to bind embedded web ui listener")?;
    let address = listener
        .local_addr()
        .context("failed to read embedded web ui listener address")?;
    let local_url = format!("http://127.0.0.1:{}/", address.port());
    let app = web_ui_backend::router(
        web_ui_backend::WebUiConfig::new(base_url.clone()).with_service_name("ironmesh-android"),
    );

    let task = rt.spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    *state = Some(WebUiServer {
        base_url,
        local_url: local_url.clone(),
        task,
    });

    Ok(local_url)
}

fn throw_java_error(env: &mut JNIEnv, message: impl AsRef<str>) {
    if env.exception_check().unwrap_or(false) {
        return;
    }
    let _ = env.throw_new("java/lang/RuntimeException", message.as_ref());
}

fn optional_jstring(env: &mut JNIEnv, value: jstring) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }

    let value = unsafe { JString::from_raw(value) };
    let value: String = env.get_string(&value)?.into();
    Ok(Some(value))
}

fn as_jbyte_slice(bytes: &[u8]) -> &[jbyte] {
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const jbyte, bytes.len()) }
}

fn as_mut_jbyte_slice(bytes: &mut [u8]) -> &mut [jbyte] {
    unsafe { std::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut jbyte, bytes.len()) }
}

struct JavaInputStreamReader<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    input_stream: JObject<'local>,
    java_buffer: JByteArray<'local>,
}

impl<'env, 'local> JavaInputStreamReader<'env, 'local> {
    const BUFFER_SIZE: usize = 64 * 1024;

    fn new(env: &'env mut JNIEnv<'local>, input_stream: JObject<'local>) -> Result<Self> {
        let java_buffer = env.new_byte_array(Self::BUFFER_SIZE as i32)?;
        Ok(Self {
            env,
            input_stream,
            java_buffer,
        })
    }
}

impl Read for JavaInputStreamReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let requested = out.len().min(Self::BUFFER_SIZE);
        let read = self
            .env
            .call_method(
                &self.input_stream,
                "read",
                "([BII)I",
                &[
                    JValue::Object(self.java_buffer.as_ref()),
                    JValue::Int(0),
                    JValue::Int(requested as i32),
                ],
            )
            .and_then(|value| value.i())
            .map_err(|err| std::io::Error::other(err.to_string()))?;

        if read < 0 {
            return Ok(0);
        }

        let read = read as usize;
        self.env
            .get_byte_array_region(&self.java_buffer, 0, as_mut_jbyte_slice(&mut out[..read]))
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        Ok(read)
    }
}

struct JavaOutputStreamWriter<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    output_stream: JObject<'local>,
    java_buffer: JByteArray<'local>,
}

impl<'env, 'local> JavaOutputStreamWriter<'env, 'local> {
    const BUFFER_SIZE: usize = 64 * 1024;

    fn new(env: &'env mut JNIEnv<'local>, output_stream: JObject<'local>) -> Result<Self> {
        let java_buffer = env.new_byte_array(Self::BUFFER_SIZE as i32)?;
        Ok(Self {
            env,
            output_stream,
            java_buffer,
        })
    }
}

impl Write for JavaOutputStreamWriter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0usize;

        while written < buf.len() {
            let chunk_len = (buf.len() - written).min(Self::BUFFER_SIZE);
            let chunk = &buf[written..written + chunk_len];
            self.env
                .set_byte_array_region(&self.java_buffer, 0, as_jbyte_slice(chunk))
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            self.env
                .call_method(
                    &self.output_stream,
                    "write",
                    "([BII)V",
                    &[
                        JValue::Object(self.java_buffer.as_ref()),
                        JValue::Int(0),
                        JValue::Int(chunk_len as i32),
                    ],
                )
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            written += chunk_len;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.env
            .call_method(&self.output_stream, "flush", "()V", &[])
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        Ok(())
    }
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
        web_ui_backend::assets::app_html()
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn configured_sdk(
    server_base_url: impl Into<String>,
    auth_token: Option<String>,
) -> Result<IronMeshClient> {
    build_http_client(None, &server_base_url.into(), &normalize_optional_string(auth_token))
}

fn configured_client_node(
    server_base_url: impl Into<String>,
    auth_token: Option<String>,
) -> Result<ClientNode> {
    Ok(ClientNode::with_client(configured_sdk(
        server_base_url,
        auth_token,
    )?))
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_startWebUi(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
) -> jstring {
    let result = (|| -> Result<String> {
        let base_url: String = env.get_string(&base_url)?.into();
        start_embedded_web_ui(base_url)
    })();

    match result {
        Ok(url) => match env.new_string(url) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust startWebUi failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust startWebUi failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_enrollDevice(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    pairing_token: JString,
    device_id: jstring,
    label: jstring,
) -> jstring {
    let result = (|| -> Result<String> {
        let base_url: String = env.get_string(&base_url)?.into();
        let pairing_token: String = env.get_string(&pairing_token)?.into();
        let device_id = normalize_optional_string(optional_jstring(&mut env, device_id)?);
        let label = normalize_optional_string(optional_jstring(&mut env, label)?);

        let rt = runtime()?;
        let base_url = client_sdk::normalize_server_base_url(&base_url)?;
        let response = rt.block_on(enroll_device(
            &base_url,
            None,
            &DeviceEnrollmentRequest {
                pairing_token,
                device_id,
                label,
            },
        ))?;

        serde_json::to_string(&response).context("failed to serialize enroll response")
    })();

    match result {
        Ok(json) => match env.new_string(json) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust enrollDevice failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust enrollDevice failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_putObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
    payload: jbyteArray,
    auth_token: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let payload_ref = unsafe { JByteArray::from_raw(payload) };
        let payload = env.convert_byte_array(&payload_ref)?;

        let rt = runtime()?;
        let client = configured_client_node(base_url, auth_token)?;
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

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_getObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
    snapshot: jstring,
    version: jstring,
    auth_token: jstring,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let rt = runtime()?;
        let client = configured_client_node(base_url, auth_token)?;
        let bytes = rt
            .block_on(client.get_with_selector(key, snapshot.as_deref(), version.as_deref()))?
            .to_vec();
        Ok(bytes)
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

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_storeIndex(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    prefix: jstring,
    depth: jint,
    snapshot: jstring,
    auth_token: jstring,
) -> jstring {
    let result = (|| -> Result<String> {
        let base_url: String = env.get_string(&base_url)?.into();
        let prefix = optional_jstring(&mut env, prefix)?;
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let sdk = configured_sdk(base_url, auth_token)?;
        let response = sdk.store_index_blocking(
            prefix.as_deref(),
            usize::try_from(depth).unwrap_or(1).max(1),
            snapshot.as_deref(),
        )?;

        serde_json::to_string(&response).context("failed to serialize store index response")
    })();

    match result {
        Ok(json) => match env.new_string(json) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust storeIndex failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust storeIndex failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamPutObject<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    base_url: JString<'local>,
    key: JString<'local>,
    input_stream: JObject<'local>,
    auth_token: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let mut reader = JavaInputStreamReader::new(&mut env, input_stream)?;
        let client = configured_client_node(base_url, auth_token)?;
        let report = client.put_chunked_reader(key, &mut reader)?;
        Ok(report.meta.size_bytes as jint)
    })();

    match result {
        Ok(size) => size,
        Err(err) => {
            throw_java_error(&mut env, format!("rust streamPutObject failed: {err:#}"));
            0
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_deleteObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
    auth_token: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let rt = runtime()?;
        let client = configured_client_node(base_url, auth_token)?;
        rt.block_on(client.delete_path(key))?;
        Ok(204)
    })();

    match result {
        Ok(code) => code,
        Err(err) => {
            throw_java_error(&mut env, format!("rust deleteObject failed: {err:#}"));
            0
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamObjectTo<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    base_url: JString<'local>,
    key: JString<'local>,
    output_stream: JObject<'local>,
    snapshot: jstring,
    version: jstring,
    auth_token: jstring,
) {
    let result = (|| -> Result<()> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let auth_token = optional_jstring(&mut env, auth_token)?;
        let mut writer = JavaOutputStreamWriter::new(&mut env, output_stream)?;
        let client = configured_client_node(base_url, auth_token)?;
        client.get_with_selector_writer(key, snapshot.as_deref(), version.as_deref(), &mut writer)
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust streamObjectTo failed: {err:#}"));
    }
}
