package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	internal "github.com/thomseddon/traefik-forward-auth/internal"
)

// Main
func main() {

	// Parse options
	config := internal.NewGlobalConfig()

	// Setup logger
	zlog := internal.NewLogger()
	zlog.Debug().Msgf("Logger initialized with level %s", config.LogLevel)

	// Perform config validation
	config.Validate()

	// Build server
	server := internal.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	zlog.Debug().Interface("config", config).Msg("Starting with config")

	// Hack to debug stuff in Google Cloud Run
	fmt.Println("Starting with config:")
	b, err := json.Marshal(config)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
	log.Print("Let's try this too.")

	zlog.Info().Msgf("Listening on :%d", config.Port)
	zlog.Info().Err(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
