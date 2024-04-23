package porcupineapi

import (
	"encoding/json"
	"os"
)

type Config struct {
	DBUser      string `json:"db_user"`
	DBPass      string `json:"db_pass"`
	DBHost      string `json:"db_host"`
	DBName      string `json:"db_name"`
	DBPort      int    `json:"db_port"`
	CallbackURL string `json:"callback_url"`
}

func LoadConfig(env string) (Config, error) {
	fileName := "../config/prod_config.json"
	if env == "development" {
		fileName = "../config/dev_config.json"
	}

	file, err := os.Open(fileName)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
