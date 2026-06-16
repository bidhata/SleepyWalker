package utils

import (
	"log"
	"os"
)

// InitLogger configures the default logger with timestamps and file/line info.
func InitLogger() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[sleepywalker] ")
}
