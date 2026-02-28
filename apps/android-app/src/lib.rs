use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::ClientNode;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jbyte, jbyteArray, jint, jstring};
use std::io::{Read, Write};
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
        web_ui::app_html()
    }
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_getObject(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    key: JString,
    snapshot: jstring,
    version: jstring,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let rt = runtime()?;
        let client = ClientNode::new(base_url);
        let bytes = rt.block_on(client.get_with_selector(
            key,
            snapshot.as_deref(),
            version.as_deref(),
        ))?
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

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamPutObject<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    base_url: JString<'local>,
    key: JString<'local>,
    input_stream: JObject<'local>,
) -> jint {
    let result = (|| -> Result<jint> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let mut reader = JavaInputStreamReader::new(&mut env, input_stream)?;
        let client = ClientNode::new(base_url);
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

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamObjectTo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    base_url: JString<'local>,
    key: JString<'local>,
    output_stream: JObject<'local>,
    snapshot: jstring,
    version: jstring,
) {
    let result = (|| -> Result<()> {
        let base_url: String = env.get_string(&base_url)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let mut writer = JavaOutputStreamWriter::new(&mut env, output_stream)?;
        let client = ClientNode::new(base_url);
        client.get_with_selector_writer(
            key,
            snapshot.as_deref(),
            version.as_deref(),
            &mut writer,
        )
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust streamObjectTo failed: {err:#}"));
    }
}
