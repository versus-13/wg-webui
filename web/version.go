package web

// Version is set at build time via:
//
//	go build -ldflags "-X 'github.com/versus/wg-webui/web.Version=1.0.0'"
//
// Falls back to "dev" when built without ldflags.
var Version = "dev"
