# xmip-core-identify-ssh-key

Identify by ssh-key: reads the fingerprint of the public key the peer presented, unverified, with the signature and session riding as proof for the second gate. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
