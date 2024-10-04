package ip

import "net/http"

// Strategy a strategy for IP selection.
type Strategy interface {
	GetIP(req *http.Request) string
}
