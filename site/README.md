# Aster landing page

The landing page is a self-contained static document with no build step,
JavaScript, external fonts, or runtime asset requests.

Preview it from the repository root:

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory site
```

Then open `http://127.0.0.1:8000/`. Deployment and hosting are intentionally
not configured in this directory.

Product-status and security claims must remain aligned with
[`docs/README.md`](../docs/README.md),
[`docs/security.md`](../docs/security.md), and
[`docs/conformance.md`](../docs/conformance.md).

The embedded Defense Unicorns wordmark was obtained from the official
[Defense Unicorns brand toolkit](https://defenseunicorns.com/brand-toolkit/).
Defense Unicorns names and logos are trademarks of Defense Unicorns, Inc.;
the Apache-2.0 license does not grant trademark rights.
