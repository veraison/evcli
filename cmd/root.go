// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/spf13/viper"
	"github.com/veraison/evcli/cmd/psa"
)

var (
	cfgFile   string
	validArgs = []string{"psa"}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "evcli",
	Short:         "Attestation Evidence swiss-army knife",
	Version:       "0.0.1",
	SilenceUsage:  true,
	SilenceErrors: true,
	ValidArgs:     validArgs,
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.evcli)")
	rootCmd.AddCommand(psa.Cmd)
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// search config in home directory with name ".evcli" (withouy extension)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".evcli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// if a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
