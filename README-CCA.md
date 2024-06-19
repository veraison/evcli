## CCA attestation tokens manipulation

The `cca` subcommand allows you to [create](#create), [check](#check) and
[verify](#verify) [CCA attestation tokens](https://github.com/veraison/ccatoken).

### Create

Use the `cca create` subcommand to create a CCA attestation token from the
supplied claims in JSON format, the Initial Attestation Key (IAK) and Realm
Attestation Key (RAK) in JSON Web Key (JWK) format<sup>[1](#inputs-ex)</sup>.

```shell
evcli cca create \
    --claims=cca-claims.json \
    --iak=ec256.json \
    --rak=ec384.json
```

On success, you should see the following printed to stdout:

```console
>> "cca-claims.cbor" successfully created
```

The CBOR-encoded CCA token is stored in the current working directory with a
name derived from the claims file you supplied.  If you want, you can specify a
different name using the `--token` command line switch (abbrev. `-t`).

For example:

```shell
evcli cca create \
    --claims=cca-claims.json \
    --iak=ec256.json \
    --rak=ec384.json
    --token=my.cbor
```

### Check

Use the `cca check` subcommand to verify the cryptographic signature on the
supplied CCA attestation token as well as checking whether all claim sets
within CCA token are well-formed. Please note that only one key (the public
part of IAK) needs to be supplied, as the public part of RAK, present
in the token is used for signature verification.

To check the CCA attestation token in my.cbor using the public key in
es256-pub.json:

```shell
evcli cca check \
    --token=my.cbor \
    --key=es256-pub.json
```

A message will indicate whether the signature has been successfully verified:

```console
>> "my.cbor" verified
```

In such case, the claim set is printed to stdout in JSON format:

```json
{
  "cca-platform-token": {
    "cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
    "cca-platform-challenge": "Bea1iETGoM0ZOCBpuv2w5JRmKjrc+P3hFHjpM5Ua8XkP9d5ceOPbESPaCiB6i2ZVbgoi8Z7mS9wviZU7azJVXw==",
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
  },
  "cca-realm-delegated-token": {
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
    "cca-realm-public-key": "BIL70TKptcOWh5+7FTQNkFCXjlXHnVJ5oroOlYVPN+IM0vZPO3K1cLvXc+7iznaEJe31Re2+if+v4OlrvUbicPIHlsRIuY2vRqdk0nRC5ubthPjOyBfm7ManHTo959Z+zQ==",
    "cca-realm-public-key-hash-algo-id": "sha-512"
  }
}

```

The claim set can also be saved to a file using the `--claims` switch (abbrev. `-c`), as in:

```shell
evcli cca check \
    --token=my.cbor \
    --key=es256-pub.json \
    --claims=output-claims.json
```

### Print

Use the `cca print` subcommand to display the claims of a CCA attestation
token as pretty-printed JSON, without performing any signature checks. This will
perform the same well-formedness check as the `check` command, but will skip
cryptographic operations, meaning that a token can be inspected on its own without
providing any keys or other additional inputs. Structured JSON text will be written to
standard output.

To print out the CCA attestation token in my.cbor:

```shell
evcli cca print \
    --token=my.cbor
```

The claim set is printed to stdout in JSON format:

```json
{
  "cca-platform-token": {
    "cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
    "cca-platform-challenge": "Bea1iETGoM0ZOCBpuv2w5JRmKjrc+P3hFHjpM5Ua8XkP9d5ceOPbESPaCiB6i2ZVbgoi8Z7mS9wviZU7azJVXw==",
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
  },
  "cca-realm-delegated-token": {
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
    "cca-realm-public-key": "BIL70TKptcOWh5+7FTQNkFCXjlXHnVJ5oroOlYVPN+IM0vZPO3K1cLvXc+7iznaEJe31Re2+if+v4OlrvUbicPIHlsRIuY2vRqdk0nRC5ubthPjOyBfm7ManHTo959Z+zQ==",
    "cca-realm-public-key-hash-algo-id": "sha-512"
  }
}

```

### Verify

The `cca verify-as` subcommand allows you to interact with the Veraison
Verifier (or another Attestation Verifier implementing the Veraison
[challenge-response API](https://github.com/veraison/docs/tree/main/api/challenge-response)).

There are two modes of operation corresponding to the emulated roles:
[Attester](#attester) or [Relying Party](#relying-party).  (For background, see
[RATS architecture](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/).)

#### Attester

The `attester` subcommand implements the "attester mode" of a
challenge-response interaction, where the verifier is the protocol challenger.
Therefore, the realm challenge is provided by the Veraison API server and the
CCA attestation token needs to be created on the fly based on the attester's
claims, platform signing (IAK) and realm signing key (RAK).

```shell
evcli cca verify-as attester \
    --api-server=https://veraison.example/challenge-response/v1/newSession \
    --claims=cca-claims-without-realm-challenge.json \
    --iak=es256.json \
    --rak=ec384.json
```

Note that the supplied claims file must not include a realm challenge claim.

Note that for CCA the realm challenge is 64 bytes long. Hence the attester
command sets a 64 byte challenge size, when requesting a challenge to Veraison
verifier.

#### Relying Party

The `relying-party` subcommand implements the "relying party mode" of a
challenge-response interaction, where the relying party was the original
challenger, and therefore the realm challenge is provided by the caller
implicitly in an already well-formed and signed CCA attestation token, possibly
produced by a previous invocation to [`evcli cca create`](#create).

```shell
evcli cca verify-as relying-party \
    --api-server=https://veraison.example/challenge-response/v1/newSession \
    --token=my.cbor
```

<a name="inputs-ex">1</a>: Examples of CCA claims, signing keys, etc., can be
found in the [misc](misc) folder.

#### Note on TLS

If the scheme in the API server URL is HTTPS, `evcli` will attempt to establish
a TLS connection to the server, validating the server certificate using system CA
certs. It is possible to disable server certificate validation with
`-i`/`--insecure` flag. Alternatively, if the CA cert for the server is
available but is not installed in the system, it may be specified using
`-E`/`--ca-cert` flag.
