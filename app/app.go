package app

import (
	"github.com/gofiber/fiber/v2"
	"github.com/muchlist/auth_service_go/db"
	"log"
)

var (
	router *fiber.App
)

func init() {
	router = fiber.New()
}

// StartApp memulai fiber http server
func StartApp() {

	client, ctx, cancel := db.Init()
	defer client.Disconnect(ctx)
	defer cancel()

	// mapping urls file url_mappings.go
	mapUrls()

	log.Fatal(router.Listen(":3000"))
}
