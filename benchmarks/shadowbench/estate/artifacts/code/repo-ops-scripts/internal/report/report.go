// Package report formats digests for the ops channel.
package report

import (
	"fmt"
	"strings"
)

// Render returns a channel-ready digest with a title line.
func Render(title, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", title)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	return b.String()
}
