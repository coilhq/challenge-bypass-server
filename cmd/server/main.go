package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"github.com/privacypass/challenge-bypass-server/server"
)

type ServerConfig struct {
	BindAddress        string `json:"bind_address,omitempty"`
	ListenPort         int    `json:"listen_port,omitempty"`
	MetricsPort        int    `json:"metrics_port,omitempty"`
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`
	CommFilePath       string `json:"comm_file_path"`
	keyVersion         string
}

var defaultConfig = &ServerConfig{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MetricsPort: 2417,
	MaxTokens:   100,
	keyVersion:  "1.0",
}

func loadConfigFile(filePath string) (ServerConfig, error) {
	conf := *defaultConfig
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

func main() {
	var configFile string
	var err error
	cfg := *defaultConfig

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&cfg.BindAddress, "addr", "127.0.0.1", "address to listen on")
	flag.StringVar(&cfg.SignKeyFilePath, "key", "", "path to the current secret key file for signing tokens")
	flag.StringVar(&cfg.RedeemKeysFilePath, "redeem_keys", "", "(optional) path to the file containing all other keys that are still used for validating redemptions")
	flag.StringVar(&cfg.CommFilePath, "comm", "", "path to the commitment file")
	flag.IntVar(&cfg.ListenPort, "p", 2416, "port to listen on")
	flag.IntVar(&cfg.MetricsPort, "m", 2417, "metrics port")
	flag.IntVar(&cfg.MaxTokens, "maxtokens", 100, "maximum number of tokens issued per request")
	flag.StringVar(&cfg.keyVersion, "keyversion", "1.0", "version sent to the client for choosing consistent key commitments for proof verification")
	flag.Parse()

	srv := server.Server{
		BindAddress: cfg.BindAddress,
		ListenPort:  cfg.ListenPort,
		MetricsPort: cfg.MetricsPort,
		MaxTokens:   cfg.MaxTokens,
		KeyVersion:  cfg.keyVersion,
	}

	if configFile != "" {
		cfg, err = loadConfigFile(configFile)
		if err != nil {
			panic(err)
		}
	}

	if configFile == "" && (cfg.SignKeyFilePath == "" || cfg.CommFilePath == "") {
		flag.Usage()
		return
	}

	err = srv.LoadKeys(cfg.SignKeyFilePath, cfg.CommFilePath, cfg.RedeemKeysFilePath)
	if err != nil {
		panic(err)
	}

	err = srv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
