# Attestation Evidence manipulation tool

## Installing and configuring

To install the `evcli` command, do:

```shell
go install github.com/veraison/evcli@latest
```

To configure auto-completion, use the `completion` subcommand.  For example, if `bash` is your shell, you would do something like:

```shell
evcli completion bash > ~/.bash_completion.d/evcli
. ~/.bash_completion
```

If instead you are using `zsh` managed via [ohmyzsh](https://ohmyz.sh):

```shell
evcli completion zsh > ~/.oh-my-zsh/completions/_evcli
. ~/.zshrc
```

For more help on completion:

```shell
evcli completion --help
```

## PSA attestation tokens manipulation

The `psa` subcommand allows you to [create](#create), [check](#check) and [verify](#verify) PSA attestation tokens.

### Create

Use the `psa create` subcommand to create a PSA attestation token from the supplied claims in JSON format and IAK in JSON Web Key (JWK) format<sup>[1](#inputs-ex)</sup>.

```shell
evcli psa create \
    --claims=psa-claims-profile-2.json \
    --key=ec256.json
```

On success, you should see the following printed to stdout:

```console
>> "psa-claims-profile-2.cbor" successfully created
```

The CBOR-encoded PSA token is stored in the current working directory with a name derived from the claims file you supplied.  If you want, you can specify a different name using the `--token` command line switch (abbrev. `-t`).

For example:

```shell
evcli psa create \
    --claims=psa-claims-profile-2.json \
    --key=ec256.json \
    --token=my.cbor
```

By default, PSA tokens are created according to the "http://arm.com/psa/2.0.0" profile.  If you are using the legacy "PSA_IOT_PROFILE_1" instead, you will need to explicitly pass it via the command line using the `--profile` switch (abbrev.  `-p`):

```shell
evcli psa create \
    --claims=psa-claims-profile-1.json \
    --key=ec256.json \
    --profile=PSA_IOT_PROFILE_1
```

### Check

Use the `psa check` subcommand to verify the cryptographic signature over the supplied PSA attestation token as well as checking whether its claim set is well-formed.

To check the PSA attestation token in my.cbor using the public key in es256.json:


```shell
evcli psa check \
    --token=my.cbor \
    --key=es256.json
```

A message will indicate whether the signature has been successfully verified:

```console
>> "my.cbor" verified
```

In such case, the claim set is printed to stdout in JSON format:

```json
{
  "eat-profile": "http://arm.com/psa/2.0.0",
  "psa-client-id": 1,
  "psa-security-lifecycle": 12288,
  "psa-implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
  "psa-boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
  "psa-hwver": "1234567890123",
  "psa-software-components": [
    {
      "measurement-type": "BL",
      "measurement-value": "AAECBAABAgQAAQIEAAECBAABAgQAAQIEAAECBAABAgQ=",
      "signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
    },
    {
      "measurement-type": "PRoT",
      "measurement-value": "BQYHCAUGBwgFBgcIBQYHCAUGBwgFBgcIBQYHCAUGBwg=",
      "signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
    }
  ],
  "psa-nonce": "AAECAwABAgMAAQIDAAECAwABAgMAAQIDAAECAwABAgM=",
  "psa-instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
  "psa-verification-service-indicator": "https://psa-verifier.org",
  "psa-certification-reference": "1234567890123-12345",
}
```

The claim set can also be saved to a file using the `--claims` switch (abbrev.  `-c`), as in:

```shell
evcli psa check \
    --token=my.cbor \
    --key=es256.json \
    --claims=output-claims.json
```

### Verify

The `psa verify-as` subcommand allows you to interact with the Veraison Verifier (or another Attestation Verifier implementing the Veraison [challenge-response API](https://github.com/veraison/docs/tree/main/api/challenge-response)).

There are two modes of operation corresponding to the emulated roles: [Attester](#attester) or [Relying Party](#relying-party).  (For background, see [RATS architecture](https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/).)

#### Attester

The `attester` subcommand implements the "attester mode" of a challenge-response interaction, where the verifier is the protocol challenger.  Therefore, the nonce is provided by the Veraison API server and the PSA attestation token needs to be created on the fly based on the attester's claims and signing IAK.

```shell
evcli psa verify-as attester \
    --api-server=https://veraison.example/challenge-response/v1 \
    --claims=psa-claims-profile-2-without-nonce.json \
    --key=es256.json
```

Note that the supplied claims file must not include a nonce claim.

By default, the command will request 48 bytes nonce from the server.  If needed, a different value can be requested using the `--nonce-size` (abbrev. `-n`) switch.  Available nonce sizes are 32, 48 or 64 bytes, as per [PSA attestation token specification](https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token/).

```shell
evcli psa verify-as attester \
    --api-server=https://veraison.example/challenge-response/v1 \
    --claims=psa-claims-profile-2-without-nonce.json \
    --key=es256.json \
    --nonce-size=32
```

#### Relying Party

The `relying-party` subcommand implements the "relying party mode" of a challenge-response interaction, where the relying party was the original challenger, and therefore the nonce is provided by the caller implicitly in an already well-formed and signed PSA attestation token, possibly produced by a previous invocation to [`evcli psa create`](#create).

```shell
evcli psa verify-as relying-party \
    --api-server=https://veraison.example/challenge-response/v1 \
    --token=my.cbor
```

<a name="inputs-ex">1</a>: Examples of PSA claims, signing keys, etc., can be found in the [misc](misc) folder.

