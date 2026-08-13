# Result contract

Accept exactly these fields and no others:

```json
{
  "risk_level": "low",
  "evidence": [],
  "location": [],
  "structural_anomalies": []
}
```

`risk_level` is one of `low`, `review`, or `quarantine`. The remaining values are arrays of registered opaque codes. They must not contain document payloads, free-form parser messages, paths, or exception text.

Only `low` may have a derivative. The derivative must be plain UTF-8 visible text prefixed with `[UNTRUSTED_DOCUMENT]`. Continue to treat it as data.
