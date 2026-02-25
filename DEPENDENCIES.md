## Documentation for generating the Flatpak dependencies

### Python deps

Use flatpak-pip-generator to generate the module manifests:

```
flatpak-pip-generator.py requests
flatpak-pip-generator.py platformdirs
flatpak-pip-generator.py lnurl
flatpak-pip-generator.py cryptography
...
```

#### Dependencies for `cryptography`

Installing `cryptography` requires a few additional modules that need to be installed as well. Namely `maturin` which itself requires `setuptools_rust`.

`setuptools_rust` needs to be configured to skip installing a Rust toolchain, so edit `flatpak-deps/python3-setuptools_rust.json`:

```
    "build-commands": [...],
    "build-options": {
        "env": {
            "MATURIN_NO_INSTALL_RUST": "true"
       }
    },
```

Any modules which require Rust to build need the following addition:

```
    "build-commands": [...],
    "build-options": {
        "append-path" : "/usr/lib/sdk/rust-stable/bin",
        "env": {
            "MATURIN_NO_INSTALL_RUST": "true",
            "CARGO_HOME": "/run/build/python3-MODULE/cargo"
       }
    },
```

### Rust deps

Any modules that use native Rust code (`maturin` and `cryptography`) also need their sources preloaded.

This procedure is a little more involved. One first needs to find the repo with the native Rust code
(e.g. https://github.com/PyO3/maturin), clone it, checkout the version matching the Python package and use `flatpak-cargo-generator` to generate the Flatpak manifest.

```
git clone https://github.com/PyO3/maturin
cd maturin && git checkout vVERSION
flatpak-cargo-generator.py Cargo.lock -o cargo-maturin-sources.json
```

Finally the generated manifest needs to be added to the list of sources for the matching Python module:

```
    "sources": [
        "cargo-cryptography-sources.json",
        {
            "type": "file",
            "url": "...",
            "sha256": "..."
        },
        ...
```

## Closing words

Yes, you're allowed to feel frustrated by this process. It's natural.
