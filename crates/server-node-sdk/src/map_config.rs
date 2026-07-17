use super::*;

/// Cluster-replicated gallery map configuration.  Keeping this alongside the
/// map artifacts means every server node resolves the same gallery variants.
pub(crate) const MAP_CONFIGURATION_STORAGE_KEY: &str = "sys/maps/gallery-map-config.json";
const MAP_CONFIGURATION_VERSION: u32 = 1;
const MAX_MAP_VARIANTS: usize = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MapVariantKind {
    Raster,
    Vector,
    Hybrid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MapVariantStyle {
    /// A pure raster map needs no vector-style interpretation.
    Raster,
    /// The established OpenMapTiles source-layer schema.
    Openmaptiles,
    /// The compact Natural Earth label-overlay source-layer schema.
    NaturalEarth,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MapVariantAssetKind {
    Raster,
    Vector,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ClusterMapVariant {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) mode_label: String,
    pub(crate) description: String,
    pub(crate) attribution: String,
    pub(crate) kind: MapVariantKind,
    pub(crate) style: MapVariantStyle,
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) raster_manifest_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) vector_manifest_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ClusterMapConfiguration {
    #[serde(default = "default_configuration_version")]
    pub(crate) version: u32,
    pub(crate) active_variant_id: String,
    pub(crate) variants: Vec<ClusterMapVariant>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClusterMapConfigurationResponse {
    pub(crate) configuration: ClusterMapConfiguration,
    pub(crate) stored: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MapVariantImportTarget {
    pub(crate) variant_id: String,
    pub(crate) asset: MapVariantAssetKind,
    pub(crate) dataset_filename: String,
    pub(crate) logical_key: String,
    pub(crate) manifest_key: String,
}

#[derive(Debug, Clone)]
pub(crate) struct LoadedMapConfiguration {
    pub(crate) configuration: ClusterMapConfiguration,
    pub(crate) stored: bool,
}

fn default_configuration_version() -> u32 {
    MAP_CONFIGURATION_VERSION
}

pub(crate) fn default_configuration() -> ClusterMapConfiguration {
    ClusterMapConfiguration {
        version: MAP_CONFIGURATION_VERSION,
        active_variant_id: "natural-earth-globe".to_string(),
        variants: vec![
            ClusterMapVariant {
                id: "natural-earth-globe".to_string(),
                label: "Natural Earth Globe".to_string(),
                mode_label: "Globe".to_string(),
                description: "Small, free worldwide overview map. Intended as the fast initial gallery map.".to_string(),
                attribution: "Made with Natural Earth. Free vector and raster map data in the public domain.".to_string(),
                kind: MapVariantKind::Raster,
                style: MapVariantStyle::Raster,
                enabled: true,
                raster_manifest_key: Some("sys/maps/natural-earth-globe.mbtiles.manifest.json".to_string()),
                vector_manifest_key: None,
            },
            ClusterMapVariant {
                id: "natural-earth-labels".to_string(),
                label: "Natural Earth Globe + labels".to_string(),
                mode_label: "Labels".to_string(),
                description: "Natural Earth base map with the optional compact city, border and road overlay.".to_string(),
                attribution: "Made with Natural Earth. Free vector and raster map data in the public domain.".to_string(),
                kind: MapVariantKind::Hybrid,
                style: MapVariantStyle::NaturalEarth,
                enabled: false,
                raster_manifest_key: Some("sys/maps/natural-earth-globe.mbtiles.manifest.json".to_string()),
                vector_manifest_key: Some("sys/maps/natural-earth-labels.mbtiles.manifest.json".to_string()),
            },
            ClusterMapVariant {
                id: "openmaptiles-street".to_string(),
                label: "OpenMapTiles Street".to_string(),
                mode_label: "Street".to_string(),
                description: "Detailed global OpenMapTiles street map. Enable after its larger MBTiles artifact is imported.".to_string(),
                attribution: "Map data © OpenStreetMap contributors, available under the Open Database License.".to_string(),
                kind: MapVariantKind::Vector,
                style: MapVariantStyle::Openmaptiles,
                enabled: false,
                raster_manifest_key: None,
                vector_manifest_key: Some("sys/maps/openmaptiles-street.mbtiles.manifest.json".to_string()),
            },
        ],
    }
}

pub(crate) async fn public_config(State(state): State<ServerState>) -> impl IntoResponse {
    match load_current_configuration(&state).await {
        Ok(loaded) => (
            StatusCode::OK,
            Json(ClusterMapConfigurationResponse {
                configuration: loaded.configuration,
                stored: loaded.stored,
            }),
        )
            .into_response(),
        Err(err) => {
            warn!(error = %err, "failed loading gallery map configuration");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn admin_get_config(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/maps/config/get";
    if let Err(status) =
        authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        return status.into_response();
    }

    match load_or_initialize_configuration(&state).await {
        Ok(loaded) => (
            StatusCode::OK,
            Json(ClusterMapConfigurationResponse {
                configuration: loaded.configuration,
                stored: loaded.stored,
            }),
        )
            .into_response(),
        Err(err) => {
            warn!(error = %err, "failed loading gallery map configuration for admin");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub(crate) async fn admin_put_config(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(configuration): Json<ClusterMapConfiguration>,
) -> impl IntoResponse {
    let action = "auth/maps/config/put";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "active_variant_id": configuration.active_variant_id,
            "variant_count": configuration.variants.len(),
        }),
    )
    .await
    {
        Ok(authz) => authz,
        Err(status) => return status.into_response(),
    };

    if let Err(err) = validate_configuration(&configuration) {
        warn!(error = %err, "rejected invalid gallery map configuration");
        return StatusCode::BAD_REQUEST.into_response();
    }

    let payload = match serde_json::to_vec_pretty(&configuration) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed encoding gallery map configuration");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let outcome = {
        let mut store = lock_store(&state, "maps.config.put").await;
        match store
            .put_object_versioned(
                MAP_CONFIGURATION_STORAGE_KEY,
                Bytes::from(payload),
                PutOptions {
                    parent_version_ids: Vec::new(),
                    state: VersionConsistencyState::Confirmed,
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: None,
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(error = %err, "failed storing gallery map configuration");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };
    map_dataset_import::register_put_outcome(
        &state,
        MAP_CONFIGURATION_STORAGE_KEY,
        &outcome.version_id,
    )
    .await;

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "updated",
        json!({
            "active_variant_id": configuration.active_variant_id,
            "variant_count": configuration.variants.len(),
            "storage_key": MAP_CONFIGURATION_STORAGE_KEY,
            "version_id": outcome.version_id,
        }),
    )
    .await;

    (
        StatusCode::OK,
        Json(ClusterMapConfigurationResponse {
            configuration,
            stored: true,
        }),
    )
        .into_response()
}

pub(crate) async fn load_current_configuration(
    state: &ServerState,
) -> Result<LoadedMapConfiguration> {
    let payload = {
        let store = read_store(state, "maps.config.get").await;
        match store
            .get_object(
                MAP_CONFIGURATION_STORAGE_KEY,
                None,
                None,
                ObjectReadMode::ConfirmedOnly,
            )
            .await
        {
            Ok(payload) => Some(payload),
            Err(StoreReadError::NotFound) => None,
            Err(StoreReadError::Corrupt(message)) => {
                bail!("gallery map configuration is corrupt: {message}")
            }
            Err(StoreReadError::Internal(err)) => return Err(err),
        }
    };

    let Some(payload) = payload else {
        return Ok(LoadedMapConfiguration {
            configuration: default_configuration(),
            stored: false,
        });
    };
    let configuration = serde_json::from_slice::<ClusterMapConfiguration>(&payload)
        .context("failed parsing gallery map configuration")?;
    validate_configuration(&configuration)?;
    Ok(LoadedMapConfiguration {
        configuration,
        stored: true,
    })
}

/// The client endpoint can safely fall back while a just-added node catches up.
/// The first authenticated admin read, however, materializes the documented
/// default so administrators immediately get a real replicated config file.
async fn load_or_initialize_configuration(state: &ServerState) -> Result<LoadedMapConfiguration> {
    let loaded = load_current_configuration(state).await?;
    if loaded.stored {
        return Ok(loaded);
    }

    // Do not manufacture a default while a joining node merely has not
    // received an already-known custom document yet. The replica reconciler
    // will bring that object across; returning the safe default meanwhile is
    // preferable to creating a competing version.
    if !state
        .cluster
        .lock()
        .await
        .replica_nodes_for_subject(MAP_CONFIGURATION_STORAGE_KEY)
        .is_empty()
    {
        return Ok(loaded);
    }

    let payload = serde_json::to_vec_pretty(&loaded.configuration)
        .context("failed encoding default gallery map configuration")?;
    let outcome = {
        let mut store = lock_store(state, "maps.config.initialize_default").await;
        store
            .put_object_versioned(
                MAP_CONFIGURATION_STORAGE_KEY,
                Bytes::from(payload),
                PutOptions {
                    parent_version_ids: Vec::new(),
                    state: VersionConsistencyState::Confirmed,
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: None,
                },
            )
            .await
            .context("failed storing default gallery map configuration")?
    };
    map_dataset_import::register_put_outcome(
        state,
        MAP_CONFIGURATION_STORAGE_KEY,
        &outcome.version_id,
    )
    .await;
    Ok(LoadedMapConfiguration {
        configuration: loaded.configuration,
        stored: true,
    })
}

pub(crate) fn resolve_import_target(
    configuration: &ClusterMapConfiguration,
    variant_id: &str,
    asset: MapVariantAssetKind,
) -> Result<MapVariantImportTarget> {
    let variant = configuration
        .variants
        .iter()
        .find(|candidate| candidate.id == variant_id)
        .ok_or_else(|| anyhow!("unknown map variant {variant_id}"))?;
    let manifest_key = match asset {
        MapVariantAssetKind::Raster => variant.raster_manifest_key.as_deref(),
        MapVariantAssetKind::Vector => variant.vector_manifest_key.as_deref(),
    }
    .ok_or_else(|| anyhow!("map variant {variant_id} has no {asset:?} asset"))?;
    let logical_key = manifest_key
        .strip_suffix(".manifest.json")
        .ok_or_else(|| anyhow!("map variant {variant_id} has an invalid manifest key"))?;
    let dataset_filename = logical_key
        .rsplit('/')
        .next()
        .filter(|filename| filename.ends_with(".mbtiles"))
        .ok_or_else(|| anyhow!("map variant {variant_id} has an invalid MBTiles filename"))?;
    Ok(MapVariantImportTarget {
        variant_id: variant_id.to_string(),
        asset,
        dataset_filename: dataset_filename.to_string(),
        logical_key: logical_key.to_string(),
        manifest_key: manifest_key.to_string(),
    })
}

fn validate_configuration(configuration: &ClusterMapConfiguration) -> Result<()> {
    if configuration.version != MAP_CONFIGURATION_VERSION {
        bail!(
            "unsupported gallery map configuration version {}",
            configuration.version
        );
    }
    if configuration.variants.is_empty() || configuration.variants.len() > MAX_MAP_VARIANTS {
        bail!("gallery map configuration must contain between 1 and {MAX_MAP_VARIANTS} variants");
    }

    let mut ids = HashSet::new();
    let mut active_is_enabled = false;
    let mut enabled_count = 0usize;
    for variant in &configuration.variants {
        validate_variant(variant)?;
        if !ids.insert(variant.id.as_str()) {
            bail!("gallery map variant ids must be unique");
        }
        if variant.enabled {
            enabled_count = enabled_count.saturating_add(1);
        }
        if variant.id == configuration.active_variant_id && variant.enabled {
            active_is_enabled = true;
        }
    }
    if enabled_count == 0 {
        bail!("gallery map configuration must enable at least one variant");
    }
    if !active_is_enabled {
        bail!("active gallery map variant must exist and be enabled");
    }
    Ok(())
}

fn validate_variant(variant: &ClusterMapVariant) -> Result<()> {
    let id_is_valid = !variant.id.is_empty()
        && variant.id.len() <= 64
        && variant.id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        });
    if !id_is_valid {
        bail!("gallery map variant id {} is invalid", variant.id);
    }
    for (field, value) in [
        ("label", variant.label.as_str()),
        ("mode_label", variant.mode_label.as_str()),
        ("description", variant.description.as_str()),
        ("attribution", variant.attribution.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 2_000 {
            bail!("gallery map variant {} has an invalid {field}", variant.id);
        }
    }

    match variant.kind {
        MapVariantKind::Raster => {
            require_manifest_key(variant, MapVariantAssetKind::Raster)?;
            if variant.vector_manifest_key.is_some() || variant.style != MapVariantStyle::Raster {
                bail!(
                    "raster map variant {} must only use the raster style and asset",
                    variant.id
                );
            }
        }
        MapVariantKind::Vector => {
            require_manifest_key(variant, MapVariantAssetKind::Vector)?;
            if variant.raster_manifest_key.is_some() || variant.style == MapVariantStyle::Raster {
                bail!(
                    "vector map variant {} must use a vector style and asset",
                    variant.id
                );
            }
        }
        MapVariantKind::Hybrid => {
            require_manifest_key(variant, MapVariantAssetKind::Raster)?;
            require_manifest_key(variant, MapVariantAssetKind::Vector)?;
            if variant.style == MapVariantStyle::Raster {
                bail!(
                    "hybrid map variant {} must use a vector overlay style",
                    variant.id
                );
            }
        }
    }
    Ok(())
}

fn require_manifest_key(variant: &ClusterMapVariant, asset: MapVariantAssetKind) -> Result<()> {
    let key = match asset {
        MapVariantAssetKind::Raster => variant.raster_manifest_key.as_deref(),
        MapVariantAssetKind::Vector => variant.vector_manifest_key.as_deref(),
    }
    .ok_or_else(|| anyhow!("map variant {} is missing its {asset:?} asset", variant.id))?;
    if !is_valid_manifest_key(key) {
        bail!("map variant {} has an invalid manifest key", variant.id);
    }
    Ok(())
}

fn is_valid_manifest_key(key: &str) -> bool {
    key.starts_with("sys/maps/")
        && key.ends_with(".mbtiles.manifest.json")
        && key.len() <= 512
        && !key.contains("..")
        && !key.contains('\\')
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_valid_and_uses_the_small_globe() {
        let configuration = default_configuration();
        assert_eq!(configuration.active_variant_id, "natural-earth-globe");
        assert!(validate_configuration(&configuration).is_ok());
    }

    #[test]
    fn import_target_uses_the_configured_cluster_key() {
        let configuration = default_configuration();
        let target = resolve_import_target(
            &configuration,
            "natural-earth-globe",
            MapVariantAssetKind::Raster,
        )
        .expect("default Natural Earth raster target");
        assert_eq!(target.logical_key, "sys/maps/natural-earth-globe.mbtiles");
        assert_eq!(
            target.manifest_key,
            "sys/maps/natural-earth-globe.mbtiles.manifest.json"
        );
    }

    #[test]
    fn configuration_rejects_a_disabled_active_variant() {
        let mut configuration = default_configuration();
        configuration.variants[0].enabled = false;
        assert!(validate_configuration(&configuration).is_err());
    }
}
