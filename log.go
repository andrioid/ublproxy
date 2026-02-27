package main

import (
	"fmt"
	"os"
	"time"
)

func logRequest(method, url string, status int, duration time.Duration) {
	fmt.Fprintf(os.Stderr, "%s %s %d %s\n", method, url, status, duration.Round(time.Millisecond))
}

func logError(context string, err error) {
	fmt.Fprintf(os.Stderr, "ERROR [%s] %v\n", context, err)
}

func logPassthrough(host string) {
	fmt.Fprintf(os.Stderr, "PASSTHROUGH %s\n", host)
}
