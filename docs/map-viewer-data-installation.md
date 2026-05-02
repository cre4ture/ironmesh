# Map Viewer Data Installation

This is the manual administrator flow for installing the self-hosted map data
used by the gallery map view.

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

## 3. Split the MBTiles Files

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

## 4. Upload the Parts to the Cluster

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

## 5. Upload the Manifests

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

## 6. Verify the Map View

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
