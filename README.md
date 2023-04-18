# Attestation Evidence manipulation tool

## Installing and configuring

To install the `evcli` command, do:

```shell
go install github.com/veraison/evcli@latest
```

To configure auto-completion, use the `completion` subcommand.  For example, if
`bash` is your shell, you would do something like:

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

For working with PSA attestation tokens follow the instructions given
[here](./README-PSA.md)


## CCA attestation tokens manipulation

For working with CCA attestation tokens follow the instructions given
[here](./README-CCA.md)
