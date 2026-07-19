# Automatic Natural Earth Import

## Purpose

The Gallery's normal map-dataset importer accepts an already prepared MBTiles
file. Natural Earth publishes source Shapefiles, so the standard physical world
map needs a controlled server-side conversion before it can use that importer
format. This feature adds that conversion for the existing
`natural-earth-globe` raster variant.

## Wizard workflow

An administrator starts from **Server Admin → Gallery → Map dataset import
wizard**. The first step chooses a map profile, not a low-level input format.
The initial profiles are:

- **Natural Earth physical world map** — a controlled automatic conversion;
- **An existing MBTiles package** — the resumable HTTP MBTiles importer.

The remaining wizard steps ask for the source, destination, and a review only
when that profile needs them. The Natural Earth profile has a fixed source and
fixed `natural-earth-globe` raster destination; it therefore asks only for
confirmation. The MBTiles profile asks for an HTTP source, a configured variant
artifact, and its part size. In both cases the final button starts an existing
background job and returns immediately to its progress panel.

New input adapters, such as PMTiles or controlled GeoPackage/Shapefile
conversion, should be added as profiles with their own validation and review
steps. They should not add raw file-format controls to unrelated profiles.

## Fixed Natural Earth workflow

The Natural Earth profile uses exactly one source URL:

```text
https://naciscdn.org/naturalearth/10m/physical/10m_physical.zip
```

The background job runs this pipeline away from the HTTP request:

```text
Natural Earth 10m physical Shapefile ZIP
  -> required ocean, land, lakes, rivers, and coastline layers
  -> fixed GDAL rasterization and EPSG:3857 reprojection
  -> PNG raster MBTiles plus overviews
  -> SQLite/PNG validation
  -> split artifact parts and atomic configured-manifest publication
```

The active Gallery variant is not changed. The result replaces only the raster
artifact selected by the replicated `natural-earth-globe` configuration, so the
map becomes available to every server node through the existing configuration
and manifest path.

## Operational behavior

Only one map import runs at a time: the automatic job and the existing
resumable URL importer exclude one another. The Admin UI reports the current
or most recently completed job with its phase, output size, and safe failure
message. Its expandable conversion log records the phase, every dependency
probe and converter command, and bounded command output; a failure names the
exact command, exit status, and captured standard/error output. A failed
conversion never publishes a new manifest, leaving the previously usable map
in place.

The generated MBTiles artifact is limited to 512 MiB and is split into at most
256 MiB parts. The download is limited to 128 MiB. Staging data is removed when
the job finishes, whether it succeeds or fails.

## Security and dependencies

The source URL, GDAL executable names, output paths, colors, and command-line
arguments are server-controlled. The feature accepts neither an arbitrary URL
nor shell fragments. It needs `unzip`, `gdal_rasterize`, `gdalwarp`,
`gdal_translate`, and `gdaladdo` on `PATH`. Debian installations receive
`gdal-bin` and `unzip` as package dependencies. Dependency checks use `unzip
-v`, which is supported by Info-ZIP, rather than the unsupported `--version`
spelling.

This first version intentionally does not accept uploaded archives, arbitrary
Shapefiles/GeoPackages, custom styles, PMTiles output, or vector labels. Those
remain separate, controlled follow-up adapters.
