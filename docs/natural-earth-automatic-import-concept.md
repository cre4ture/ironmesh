# Automatic Natural Earth Import

## Purpose

The Gallery's normal map-dataset importer accepts an already prepared MBTiles
file. Natural Earth publishes source Shapefiles, so its physical world map and
labels overlay need controlled server-side conversion. This feature produces the
existing `natural-earth-globe` raster variant and the `natural-earth-labels`
hybrid variant from fixed official sources.

## Wizard workflow

An administrator starts from **Server Admin → Gallery → Map dataset import
wizard**. The first step chooses a map profile, not a low-level input format:

- **Natural Earth physical world map** — a controlled raster conversion;
- **Natural Earth physical world map + labels** — the physical conversion plus
  a controlled vector label overlay;
- **An existing MBTiles package** — the resumable HTTP MBTiles importer.

The two Natural Earth profiles have fixed official sources and fixed configured
destinations, so they only ask for confirmation. The labels profile publishes a
raster and a vector artifact for `natural-earth-labels`; the raster-only profile
publishes the `natural-earth-globe` artifact. The MBTiles profile asks for an
HTTP source, a configured variant artifact, and its part size. Every final
button starts a background job and returns immediately to its progress panel.

New input adapters, such as PMTiles or controlled GeoPackage/Shapefile
conversion, should be added as profiles with their own validation and review
steps. They should not add raw file-format controls to unrelated profiles.

## Fixed Natural Earth workflows

The raster-only profile uses this source:

```text
https://naciscdn.org/naturalearth/10m/physical/10m_physical.zip
```

Its background job runs this pipeline away from the HTTP request:

```text
Natural Earth 10m physical Shapefile ZIP
  -> required ocean, land, lakes, rivers, and coastline layers
  -> fixed GDAL rasterization and EPSG:3857 reprojection
  -> PNG raster MBTiles plus overviews
  -> SQLite/PNG validation
```

The labels profile additionally uses three controlled 10m cultural source
archives:

```text
https://naciscdn.org/naturalearth/10m/cultural/ne_10m_admin_0_countries.zip
https://naciscdn.org/naturalearth/10m/cultural/ne_10m_populated_places.zip
https://naciscdn.org/naturalearth/10m/cultural/ne_10m_admin_0_boundary_lines_land.zip
```

It writes a temporary GeoPackage with the compact viewer schema, then creates
a PBF vector MBTiles overlay:

```text
countries -> `ne_places` country label points
populated places -> `ne_places` city, town, and village label points
country boundaries -> `ne_boundaries` lines
all three layers -> GeoPackage -> PBF vector MBTiles
```

The job validates the raster PNG MBTiles and the vector PBF MBTiles, including
the required `ne_places` and `ne_boundaries` metadata, before publishing either
configured artifact. The active Gallery variant is not changed; an
administrator can enable the Labels variant after the job succeeds.

## Operational behavior

Only one map import runs at a time: the automatic job and the existing
resumable URL importer exclude one another. The Admin UI reports the current
or most recently completed job with its phase, output size, configured
artifacts, and safe failure message. Its expandable conversion log records the
phase, dependency probes, and converter commands; a failure names the exact
command, exit status, and captured standard/error output.

A failed conversion before publication never replaces a manifest, leaving the
previously usable map in place. Each generated MBTiles artifact is limited to
512 MiB and is split into at most 256 MiB parts. Every source archive is
limited to 128 MiB. Staging data is removed when the job finishes, whether it
succeeds or fails.

## Security and dependencies

The source URLs, GDAL executable names, output paths, colors, and command-line
arguments are server-controlled. The feature accepts neither an arbitrary URL
nor shell fragments. The physical profile needs `unzip`, `gdal_rasterize`,
`gdalwarp`, `gdal_translate`, and `gdaladdo` on `PATH`; the labels profile also
needs `ogr2ogr`. Debian installations receive all GDAL commands from `gdal-bin`
and archive extraction from `unzip`. Dependency checks use `unzip -v`, which is
supported by Info-ZIP, rather than the unsupported `--version` spelling.

The feature intentionally does not accept uploaded archives, arbitrary
Shapefiles/GeoPackages, custom styles, PMTiles output, or arbitrary vector
layers. The optional `ne_roads` Natural Earth source layer also remains an
administrator-provided overlay because its global coverage is limited.
