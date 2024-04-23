package main

import (
	"log"
	"net/http"
	"os"

	"github.com/caarlos0/env/v6"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"

	porcupineapi "github.com/PChoice-Development/porcupineapi"
)

func main() {
	// Load .env file from config directory
	err := godotenv.Load("../config/.env")
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	Envs := porcupineapi.EnvVars{}

	err = env.Parse(&Envs)
	if err != nil {
		log.Fatalf("unable to parse environment variables: %e", err)
	}

	localEnvironment := os.Getenv("APP_ENV")
	if localEnvironment == "" {
		localEnvironment = "development"
	}

	config, err := porcupineapi.LoadConfig(localEnvironment)
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}
	Envs.CallbackURL = config.CallbackURL
	db, sqldb, err := porcupineapi.NewDatabase(config)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize session store
	storeKey := os.Getenv("SESSION_KEY") // Ensure you have a session key in your environment variables
	store := sessions.NewCookieStore([]byte(storeKey))

	router := porcupineapi.NewRouter(db, Envs, store)
	err = router.LoadRoutes("routes.txt", sqldb)
	if err != nil {
		log.Println("Attempting to LoadRoutesFromFile")
		log.Fatal(err)
	}

	log.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router.GetHandler()))
}
