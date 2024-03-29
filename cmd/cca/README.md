# Claims Template

```json
{
  "cca-platform-token": {
    // CCA Platform claims
  },
  "cca-realm-delegated-token": {
    // CCA Realm delegated claims
  }
}
```

## CCA Platform Claims

```json
{
  "cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
  "cca-platform-challenge": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
  "cca-platform-implementation-id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
  "cca-platform-config": "AQID",
  "cca-platform-lifecycle": 12288,
  "cca-platform-sw-components": [
    {
      "measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
      "signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
    }
  ],
  "cca-platform-service-indicator": "https://veraison.example/v1/challenge-response",
  "cca-platform-hash-algo-id": "sha-256"
}
```

## CCA Realm delegated claims

```json
{
  "cca-realm-challenge": "QUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQkFCQUJBQg==",
  "cca-realm-personalization-value": "QURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBREFEQURBRA==",
  "cca-realm-initial-measurement": "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
  "cca-realm-extensible-measurements": [
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw==",
    "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQw=="
  ],
  "cca-realm-hash-algo-id": "sha-256",
  "cca-realm-public-key": "WUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWUJZQllCWQ==",
  "cca-realm-public-key-hash-algo-id": "sha-512"
}
```
