# CloudFront clean-URL routing

`clean-routes.js` is a CloudFront **viewer-request** function that rewrites the
extensionless page paths the link generators emit to the files that back them:

| request | served file |
| --- | --- |
| `/join?room=…&token=…` | `join.html` (query preserved) |
| `/beacon?room=…&ttl=…#key=…` | `beacon.html` (query preserved, fragment never leaves the browser) |

Without it, S3 website hosting serves neither path — both fall through to the
landing page, and the beacon case fails silently because the key is in the
fragment and never reaches the server to produce an error.

Distribution: **E2IXK95SLTDMPX**.

The commands below have **not** been run. Run them from the repository root with
credentials for the account that owns the distribution. CloudFront Functions are
a global (`us-east-1`) resource; add `--region us-east-1` if your default region
is elsewhere.

## 1. Create

```sh
aws cloudfront create-function \
  --name netherchat-clean-routes \
  --function-config Comment="Rewrite /join and /beacon to their .html files",Runtime=cloudfront-js-2.0 \
  --function-code fileb://infra/cloudfront/clean-routes.js
```

The response carries the `ETag` and the function ARN. The function is now in the
`DEVELOPMENT` stage only — it is not serving traffic yet.

## 2. Test against the real runtime (before publishing)

`test-function` executes the function in CloudFront's own runtime and returns the
request object it produced. This is the check worth running; see
"Testing" below for why there is no repo-local test.

```sh
cat > /tmp/beacon-event.json <<'EOF'
{
  "version": "1.0",
  "context": { "eventType": "viewer-request" },
  "viewer": { "ip": "1.2.3.4" },
  "request": {
    "method": "GET",
    "uri": "/beacon",
    "querystring": { "room": { "value": "ops" }, "ttl": { "value": "3600" } },
    "headers": {},
    "cookies": {}
  }
}
EOF

ETAG=$(aws cloudfront describe-function --name netherchat-clean-routes --query ETag --output text)

aws cloudfront test-function \
  --name netherchat-clean-routes \
  --if-match "$ETAG" \
  --stage DEVELOPMENT \
  --event-object fileb:///tmp/beacon-event.json
```

Expect `FunctionOutput` to contain `"uri": "/beacon.html"` with the `querystring`
unchanged. Repeat with `"uri": "/join"`, and with `"uri": "/beacon/ops"` — the
last one must come back **unchanged** (that path is the relay's beacon REST API,
not a page).

## 3. Publish

Publishing copies `DEVELOPMENT` to `LIVE`. Re-read the ETag first; it changes on
every write.

```sh
ETAG=$(aws cloudfront describe-function --name netherchat-clean-routes --query ETag --output text)

aws cloudfront publish-function --name netherchat-clean-routes --if-match "$ETAG"
```

## 4. Associate with the distribution

There is no one-shot "associate" command — fetch the distribution config, add the
association to the default cache behavior, and write it back.

```sh
aws cloudfront get-distribution-config --id E2IXK95SLTDMPX > /tmp/dist.json

DIST_ETAG=$(jq -r '.ETag' /tmp/dist.json)
FN_ARN=$(aws cloudfront describe-function --name netherchat-clean-routes \
  --query 'FunctionSummary.FunctionMetadata.FunctionARN' --output text)

jq --arg arn "$FN_ARN" '
  .DistributionConfig
  | .DefaultCacheBehavior.FunctionAssociations = {
      Quantity: 1,
      Items: [ { EventType: "viewer-request", FunctionARN: $arn } ]
    }
' /tmp/dist.json > /tmp/dist-updated.json

aws cloudfront update-distribution \
  --id E2IXK95SLTDMPX \
  --if-match "$DIST_ETAG" \
  --distribution-config file:///tmp/dist-updated.json
```

> If the distribution already has `FunctionAssociations` on its default behavior,
> the `jq` above **replaces** them. Inspect
> `jq '.DistributionConfig.DefaultCacheBehavior.FunctionAssociations' /tmp/dist.json`
> first and append instead of overwriting if anything is there.

## 5. Invalidate the stale cached paths

`/join` and `/beacon` have been served as the landing page and are cached under
those exact URIs. The rewrite does not evict them.

```sh
aws cloudfront create-invalidation --distribution-id E2IXK95SLTDMPX \
  --paths '/join' '/beacon'
```

## 6. Verify against the deployed distribution

Wait for `aws cloudfront get-distribution --id E2IXK95SLTDMPX --query 'Distribution.Status'`
to report `Deployed`, then:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' 'https://<domain>/join?room=ops&token=x'
curl -sS 'https://<domain>/beacon?room=ops&ttl=3600' | head -5   # must be beacon.html, not the landing page
curl -sS -o /dev/null -w '%{http_code}\n' 'https://<domain>/beacon/ops'  # unchanged — still the API path
```

## Testing

There is **no repo-local unit test for this function, deliberately.** CloudFront
Functions run in a restricted JS runtime with no module system, so a Node test
would have to `eval` the source into a fake `event` object it also authored. That
test would re-assert the same two-line mapping the source states outright and
would pass no matter what CloudFront actually does with the request — the failure
modes that matter here (wrong runtime string, function not published to `LIVE`,
association missing from the distribution, stale cached objects) all live outside
the JS and none of them would be caught.

The two checks that do assert something are both above: `aws cloudfront
test-function` in step 2 runs the real runtime and returns the real rewritten
request, and the `curl` calls in step 6 exercise the whole deployed path. Both
need AWS credentials, so neither belongs in CI.
