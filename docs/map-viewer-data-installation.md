# Map Viewer Data Installation

The Server Admin gallery page provides the recommended administrator workflow
for installing self-hosted map data. It downloads and splits each MBTiles
dataset without first writing the full source file to local disk, ingests the
incoming bytes directly as IronMesh chunks, and finalizes the part objects and
manifest under `sys/maps/`.

The current Ironmesh map viewer expects split MapTiler MBTiles artifacts stored
under `sys/maps/` in the cluster object namespace, plus one manifest per logical
MBTiles file.

## License Check

Before downloading data, verify that the intended deployment is allowed by the
current MapTiler terms.

As checked on 2026-05-02, MapTiler's On-prem Free tier is listed as `0 USD` for
non-commercial or evaluation use with a maximum of 100 monthly active users. The
free-tier maps listed there are:

- OpenStreetMap Vectors (2020)
- Satellite Low-Res (2016)

Relevant MapTiler pages:

- <https://www.maptiler.com/data/pricing/>
- <https://www.maptiler.com/terms/server-data/>
- <https://www.maptiler.com/copyright/>

Administrators are responsible for checking the current terms before download
and before production use. In particular, do not use the free datasets for a
commercial, public, government, military, B2B, or B2C deployment unless the
current MapTiler license for that deployment explicitly allows it.

## 1. Create a MapTiler Account

Create an account at:

```text
https://data.maptiler.com/
```

Use the account only according to the license that applies to the target
cluster. The free path is intended for non-commercial/evaluation usage within
MapTiler's published limits.

## 2. Select the MapTiler Data Downloads

After signing in, make sure the interface is for **MapTiler Data**, not
**MapTiler Cloud**. The browser may pass through MapTiler Cloud authentication,
but the download workflow should end at `data.maptiler.com`.

Navigate to:

```text
Downloads -> GET NEW DATASET
```

Select whole-planet downloads for:

- OpenStreetMap Vectors (2020)
- Satellite Low-Res (2016)

Expected local filenames for the manifests currently included in this repo are:

```text
maptiler-osm-2020-02-10-v3.11-planet.mbtiles
maptiler-satellite-2017-11-02-planet.mbtiles
```

The combined payload is roughly 260 GiB, or about 275 GB in decimal units. Use
MapTiler's **Copy CLI command** option instead of downloading through the
browser. Reserve extra local disk space: while splitting, the original files and
the split output may coexist.

## 3. Import from the Server Admin UI

Open the Server Admin gallery page on a configured cluster server node. Paste
either the MapTiler HTTPS URL or the complete command copied from MapTiler, for
example:

```bash
wget -c https://data.maptiler.com/download/<account-token>/maptiler-satellite-2017-11-02-planet.mbtiles
```

Set the desired part size in GiB and start the import. The UI accepts 1-64 GiB;
the server also accepts values down to 256 MiB for API clients. The selected
part size determines the final job-specific part objects under `sys/maps/` and
the automatically generated manifest. It is not restricted to the legacy 10
GiB layout. Job-specific keys keep an already published manifest serving its
previous complete part set until the replacement import has finished.

The server requires an HTTP range-capable source. It streams one configured
part at a time into 8 MiB IronMesh chunks, so the full MBTiles file is never
held in a temporary local file. The status card shows overall progress, the
active part, finalized parts, retry state, and the last error.

Progress is atomically persisted after at most 64 MiB of newly ingested data.
After a server-node restart, an active import resumes from the last persisted
checkpoint. The source URL is persisted in the node state directory because it
contains the MapTiler account token needed to resume; restrict access to that
directory to server-node administrators.

Use the standard MapTiler filenames above if the existing gallery basemap
selection should discover the dataset automatically. The generated manifest is
published only after all parts have been finalized.

## 4. Manual Split and Upload Fallback

Use this manual procedure only when the Server Admin import cannot reach the
MapTiler source directly.

Split each MBTiles file into 10 GiB parts. Run the commands from the directory
where the part files should be written:

```bash
split -b 10737418240 \
  maptiler-satellite-2017-11-02-planet.mbtiles \
  maptiler-satellite-2017-11-02-planet.mbtiles-part-

split -b 10737418240 \
  maptiler-osm-2020-02-10-v3.11-planet.mbtiles \
  maptiler-osm-2020-02-10-v3.11-planet.mbtiles-part-
```

If the OSM file is stored in the checkout-local `map/` directory, use that path
as the source instead:

```bash
split -b 10737418240 \
  ~/rust-dev/ironmesh/map/maptiler-osm-2020-02-10-v3.11-planet.mbtiles \
  maptiler-osm-2020-02-10-v3.11-planet.mbtiles-part-
```

The repo manifests assume the default `split` suffixes:

- satellite parts: `aa` through `as`
- OSM parts: `aa` through `ag`

Do not change the part size, suffix format, or filenames unless you also
regenerate the corresponding manifest JSON.

## 5. Upload the Parts to the Cluster

Upload every generated part object under:

```text
sys/maps/
```

The object key must be the target directory plus the local filename. Examples:

```text
sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles-part-aa
sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles-part-ab
sys/maps/maptiler-osm-2020-02-10-v3.11-planet.mbtiles-part-aa
sys/maps/maptiler-osm-2020-02-10-v3.11-planet.mbtiles-part-ab
```

Use whichever Ironmesh upload path is appropriate for the deployment. Two
common options are:

```bash
ironmesh \
  --bootstrap-file /path/to/ironmesh-client-bootstrap.json \
  --client-identity-file /path/to/ironmesh-client-bootstrap.client-identity.json \
  serve-web
```

Then use the web Store view's binary upload flow with `sys/maps/` as the target
prefix.

Or mount the cluster and copy into the mounted namespace.

Keep the upload process running until all parts have finished syncing before
unmounting or shutting down the client.

## 6. Upload the Manifests

Upload the two manifest files shipped with this repository:

```text
docs/examples/maptiler-osm-2020-02-10-v3.11-planet.mbtiles.manifest.json
docs/examples/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json
```

They must be stored in the cluster as:

```text
sys/maps/maptiler-osm-2020-02-10-v3.11-planet.mbtiles.manifest.json
sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json
```

The manifests are in `docs/examples/` in this repo. If an older note refers to
`docs/assets/examples/`, use `docs/examples/` instead.

## 7. Verify the Map View

Check that the cluster contains the expected objects.
The CLI for this is described here, but you can also do it differently.

```bash
ironmesh \
  --bootstrap-file /path/to/ironmesh-client-bootstrap.json \
  --client-identity-file /path/to/ironmesh-client-bootstrap.client-identity.json \
  list --prefix sys/maps --depth 1
```

The listing should include:

- 19 satellite part objects and the satellite manifest
- 7 OSM part objects and the OSM manifest

Finally, make sure the cluster contains at least a few gallery-visible images
with EXIF GPS metadata. Photos copied through tools that strip metadata will not
appear on the map.

Open the gallery, switch to the map view, and verify that:

- the basemap loads,
- GPS-tagged image thumbnails appear at their recorded locations,
- the grid view still works as the fallback.
