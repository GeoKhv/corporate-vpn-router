# Build-only DMG metadata libraries

Unmodified pure-Python wheels from PyPI, loaded directly from ZIP by Python;
no installation, build network access or executable native component is needed.
They are not copied into the DMG or VPN application. Their MIT licenses are
included both in the wheels and beside this file. SHA-256 pins are checked by
`../metadata.py` before import.

- `ds-store==1.3.1`: [PyPI](https://pypi.org/project/ds-store/1.3.1/),
  [versioned documentation](https://ds-store.readthedocs.io/en/v1.3.1/).
- `mac-alias==2.2.2`: [PyPI](https://pypi.org/project/mac-alias/2.2.2/),
  [source](https://github.com/dmgbuild/mac_alias/tree/v2.2.2).

Refresh only deliberately, reviewing licenses, Python compatibility and hashes:

```sh
python3 -m pip download --only-binary=:all: --no-deps --dest scripts/dmg/vendor \
  ds-store==1.3.1 mac-alias==2.2.2
```

The view dictionaries/alias strategy follow the upstream
[dmgbuild implementation](https://github.com/dmgbuild/dmgbuild/blob/v1.6.5/src/dmgbuild/core.py).
