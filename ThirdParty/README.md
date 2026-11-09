# Components and corresponding source
The original Swift UI is MIT. The SSL worker importing cpyvpn is distributed under GPL-3.0-or-later. The included components retain their own licenses. The tagged source and the source archive beside the installer provide the worker, modifications, native source trees and build scripts. No external Check Point binaries, keys or certificates are redistributed.

| Component | Pinned input / modification |
| --- | --- |
| [cpyvpn 1.6.4](https://pypi.org/project/cpyvpn/1.6.4/) | Sdist SHA-256 eeb83051d51bd60ee2abc9ccf81933e299c57209768c830db4b6a0b20c77ceaf. Included Python modules are the corresponding source. ssl_ctx.py and utils.py remove the permissive upstream TLS path, HTTP redirects and control-body logging. See cpyvpn.txt and GPL-3.txt. |
| [ocproxy](https://github.com/cernekee/ocproxy/tree/c98f06d942970cdf35dd66ab46840f7d6d567b60) | Exact source archive includes lwIP; local ocproxy-policy.patch enforces SOCKS policy and framing. BSD notices supplied. |
| [libevent 2.1.12-stable](https://github.com/libevent/libevent/releases/tag/release-2.1.12-stable) | Included upstream tarball linked statically into ocproxy, without its OpenSSL transport. BSD and component notices included. |
| [Python Build Standalone](https://github.com/astral-sh/python-build-standalone/releases/tag/20261026) | Relocatable arm64 CPython 3.13.18. The release URL and SHA-256 are pinned in scripts/bundle.py. All upstream build license texts are in licenses/python; the app carries them. The corresponding build recipe and CPython/dependency versions are in the upstream tag. |
| RFC 1751 word list | Public domain word list from PyCryptodome 3.23.0, attribution in licenses/RFC1751.txt. No isakmp engine or code required. |

Build on an Apple Silicon Mac with Apple's command-line developer tools: run bash scripts/build.sh, then bash scripts/package.sh. Only the build machine needs these tools and network access to fetch the pinned runtime. Test the resulting bundle using its own interpreter: Runtime/bin/python3.13 -I -B Tests/beta_tls.py /absolute/path/to/Contents/Resources/Engine, from the source tree. The loopback fixtures use temporary keys only.
