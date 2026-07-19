# Gallery Map Packages

IronMesh keeps gallery map selection in the cluster object
`sys/maps/gallery-map-config.json`. The selected map and its artifact keys are
therefore identical regardless of which server node an administrator or client
uses. The object is confirmed, replicated, versioned, and published using the
same path as other cluster objects.

The Server Admin Gallery initializes this file with a small Natural Earth
world-map profile. It is the initial client default. The browser can switch
between every enabled profile immediately; changing the initial profile in the
admin UI is picked up by the client UI on its next configuration refresh.

## Included profiles

| Profile | Purpose | Default state |
| --- | --- | --- |
| `natural-earth-globe` | Small raster world overview based on Natural Earth | enabled and active |
| `natural-earth-labels` | The Natural Earth base plus cities, borders, and optional roads | disabled until its overlay is imported |
| `openmaptiles-street` | A detailed global vector street map | disabled until its larger artifact is imported |
| `maptiler-satellite` | The original MapTiler Satellite 2017 planet package | disabled; retained for upgrades |
| `maptiler-hybrid` | The original MapTiler satellite package with its OpenMapTiles overlay | disabled; retained for upgrades |
| `maptiler-street` | The original MapTiler OpenMapTiles 2020 planet package | disabled; retained for upgrades |

Natural Earth data is public domain. The detailed street profile is deliberately
not coupled to a particular provider: the administrator must use a compatible,
properly licensed MBTiles source. OpenStreetMap-derived data normally requires
attribution and observance of the [Open Database License](https://www.openstreetmap.org/copyright).

The import card displays a provider link and acquisition hint for every included
profile: [Natural Earth](https://www.naturalearthdata.com/),
[OpenMapTiles](https://openmaptiles.org/), or legacy
[MapTiler Data](https://data.maptiler.com/). Custom profiles retain a generic
license and attribution reminder because their provider is administrator-defined.

## Configure a map variant

Open **Server Admin → Gallery → Gallery map variants**. The first authenticated
read materializes the default configuration in cluster storage. From there an
administrator can:

1. choose the shared initial gallery map;
2. enable or hide profiles without deleting their already imported artifacts;
3. use the advanced JSON editor to add future profiles or change artifact keys.

The server rejects an invalid document. A configuration must have an enabled
active variant, unique lower-case variant IDs, and valid `sys/maps/*.mbtiles.manifest.json`
artifact keys. A raster profile has one raster artifact, a vector profile one
vector artifact, and a hybrid profile has both.

An abbreviated example for a custom small globe profile is:

```json
{
  "version": 1,
  "active_variant_id": "natural-earth-globe",
  "variants": [
    {
      "id": "natural-earth-globe",
      "label": "Natural Earth Globe",
      "mode_label": "Globe",
      "description": "Small global overview map.",
      "attribution": "Made with Natural Earth. Free vector and raster map data in the public domain.",
      "kind": "raster",
      "style": "raster",
      "enabled": true,
      "raster_manifest_key": "sys/maps/natural-earth-globe.mbtiles.manifest.json"
    }
  ]
}
```

`style` is `raster`, `openmaptiles`, or `natural_earth`. The style selects the
source-layer schema used by the shared MapLibre gallery component; it does not
alter the source data.

## Use the map dataset import wizard

Open **Server Admin → Gallery → Map dataset import wizard**. The wizard asks
for a desired map outcome first and then adapts the remaining questions to that
profile:

1. choose **Natural Earth physical world map**, **Natural Earth physical world
   map + labels**, or **An existing MBTiles package**;
2. confirm the fixed official Natural Earth source, or paste one HTTP(S) URL
   (or a copied `wget -c ...` command) for an existing MBTiles package;
3. confirm the fixed `natural-earth-globe` raster destination, the fixed
   raster and vector destinations for the labels profile, or select the
   configured variant artifact and part size for an MBTiles package;
4. review the source and destination, then start the background job.

The source file name is never a destination. The selected cluster
configuration controls the logical file and manifest keys, so one profile can
be replaced while other imported profiles remain available. The wizard shows
the current or most recently completed job below the steps.

The importer requires HTTP range requests. It streams the source directly into
IronMesh chunks, checkpoints after at most 64 MiB of input, and resumes an
unfinished job after the server node restarts. It publishes the generated
split-file manifest only after all parts are complete.

The persisted source URL may contain credentials or signed-download tokens.
Restrict the server-node state directory to administrators.

## Natural Earth labels and roads

Natural Earth distributes source vector and raster data, not a universal
ready-made MBTiles package. Package the chosen Natural Earth layers into a
worldwide raster MBTiles base and, if desired, a separate vector MBTiles
overlay. Point the profile's manifest keys at those two artifacts and import
them through the admin UI.

### Automatic physical base map

For the standard `natural-earth-globe` raster profile, choose **Natural Earth
physical world map** in the wizard. The node downloads the fixed official
Natural Earth 10m physical archive, renders ocean, land, lakes, rivers, and
coastlines with the built-in colors, creates Web-Mercator PNG MBTiles, validates
them, and publishes the configured manifest only after all generated artifact
parts are stored.

This automatic path has no administrator-provided URL or converter arguments.
It requires `unzip`, `gdal_rasterize`, `gdalwarp`, `gdal_translate`, and
`gdaladdo` on the server `PATH`. The Debian package installs `unzip` and
`gdal-bin`; other deployments must provide the same tools. The existing manual
import remains appropriate for a custom physical rendering or data from another
provider.

Expand **Conversion log** on the Natural Earth job to inspect each conversion
phase, dependency check, and executed converter command. Failed commands show
their exact invocation, exit status, and bounded captured output in both the
job error and the log.

For the `natural_earth` vector style, the overlay uses this compact source-layer
contract:

- `ne_places` for country, city, town, and village names; use a `class` property
  and a `name` or `name_en` property;
- `ne_boundaries` for borders;
- `ne_roads` for optional road lines.

Choose **Natural Earth physical world map + labels** in the wizard to generate
the standard `natural-earth-labels` vector artifact automatically. In addition
to the physical base archive, the node downloads the fixed official 10m
countries, populated-places, and country-boundaries archives. It converts
country polygons to label points, classifies populated places as cities, towns,
or villages, then writes the `ne_places` and `ne_boundaries` layers to vector
MBTiles. The raster base and vector overlay are both validated before either
configured manifest is replaced.

The labels profile also needs `ogr2ogr` from `gdal-bin`; its dependency check
is visible on the Dependencies page and in the conversion log. The viewer
tolerates the optional `ne_roads` layer, which is deliberately left out of the
automatic profile because Natural Earth has only limited global road coverage.
It can be added later by replacing the same configured vector artifact with a
compatible custom package.

## Detailed street packages

For a larger worldwide street map, create or obtain an MBTiles package that
uses the OpenMapTiles source-layer schema, add its manifest key to a `vector`
profile with `style: "openmaptiles"`, import it, then enable it. The standard
OpenMapTiles layer names (`transportation`, `place`, `boundary`, and so on) are
rendered by the existing street style.

Keep the legally required attribution in the profile's `attribution` field.
IronMesh intentionally does not download a provider-specific global street
dataset by default; the map variant document keeps that policy and its artifact
URLs under administrator control.

## Verify

After an import completes:

1. enable the profile in **Gallery map variants** if it is not already enabled;
2. select it as the initial profile if wanted;
3. open the gallery map in the server admin UI or client UI;
4. confirm the base map, marker thumbnails, and (for a hybrid/vector profile)
   labels render as expected.

The admin card shows the exact logical file and manifest keys for an active or
completed import. They can also be inspected through the normal cluster store
view under `sys/maps/`.
