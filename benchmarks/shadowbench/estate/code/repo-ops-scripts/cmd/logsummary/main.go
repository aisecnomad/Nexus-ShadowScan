// Command logsummary condenses nightly dispatch logs into a short digest
// for the ops channel.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	openai "github.com/sashabaranov/go-openai"

	"git.vantor.example/platform/repo-ops-scripts/internal/report"
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("read stdin: %v", err)
	}
	client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "Summarise dispatch log errors in five bullet points."},
			{Role: openai.ChatMessageRoleUser, Content: string(raw)},
		},
	})
	if err != nil {
		log.Fatalf("summarise: %v", err)
	}
	fmt.Print(report.Render("nightly dispatch digest", resp.Choices[0].Message.Content))
}
