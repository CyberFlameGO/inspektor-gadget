---
title: Verifying
weight: 100
description: >
  Verify Inspektor Gadget release assets
---

The Inspektor Gadget release checksums file is signed using [`cosign`](https://github.com/sigstore/cosign).
In this guide, we will see how you can verify release assets with this tool.

## Verifying the checksums file

You would need to have `cosign` [v2.0](https://github.com/sigstore/cosign/blob/main/README.md#developer-installation) installed to verify the checksums file:

```bash
$ RELEASE='v0.15.0'
$ ASSET="inspektor-gadget-${RELEASE}_checksums.txt"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
# We need to get the asset itself, its signature file and the corresponding certificate:
$ for i in $URL/$ASSET $URL/$ASSET.sig $URL/$ASSET.cert; do
	wget $i
done
...
$ cat ${ASSET}.cert | base64 -d | openssl x509 -text -noout
...
            X509v3 Subject Alternative Name: critical
                URI:https://github.com/inspektor-gadget/inspektor-gadget/.github/workflows/inspektor-gadget.yml@refs/tags/v0.14.0
            1.3.6.1.4.1.57264.1.1:
                https://token.actions.githubusercontent.com
...
$ cosign verify-blob $ASSET --certificate ${ASSET}.cert --signature ${ASSET}.sig --certificate-identity https://github.com/inspektor-gadget/inspektor-gadget/.github/workflows/inspektor-gadget.yml@refs/tags/${ASSET} --certificate-oidc-issuer https://token.actions.githubusercontent.com
Verified OK
```

As you can see, the checksum file was correctly verified which means this file was indeed signed by us.
So, you can use this file to verify other release assets.
Note that, you would need to have an internet connection for `cosign` to verify the release asset.

## Verify an asset

Once you verified the checksums file, you can now verify the integrity of an asset using such checksums file:

```bash
$ RELEASE='v0.15.0'
$ ASSET="inspektor-gadget-${RELEASE}.yaml"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
$ wget $URL/$ASSET
$ grep $ASSET inspektor-gadget-${RELEASE}_checksums.txt | shasum -a 256 -c -s || echo "Error: ${ASSET} didn't pass the checksum verification. You must not use it!"
```
