package ping_controller

import (
	"github.com/gofiber/fiber/v2"
	"time"
)

//Ping mengembalikan pong untuk keperluan pengecekan availability server
func Ping(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"msg": "PONG!", "time": time.Now()})
}
