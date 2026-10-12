// Command etabot answers ETA questions in the ops channel from a local
// Ollama model, so no shipment data leaves the build network.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: etabot <trailer-id>")
	}
	base := os.Getenv("OLLAMA_HOST")
	if base == "" {
		base = "http://localhost:11434"
	}
	model, err := ollama.New(ollama.WithServerURL(base), ollama.WithModel("llama3.1:8b"))
	if err != nil {
		log.Fatalf("connect ollama: %v", err)
	}
	out, err := llms.GenerateFromSinglePrompt(context.Background(), model,
		"When does trailer "+os.Args[1]+" reach the Katowice dock? Answer in one line.")
	if err != nil {
		log.Fatalf("generate: %v", err)
	}
	fmt.Println(out)
}
