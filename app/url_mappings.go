package app

import (
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/muchlist/auth_service_go/controllers/middleware"
	"github.com/muchlist/auth_service_go/controllers/ping_controller"
	"github.com/muchlist/auth_service_go/controllers/user_controller"
)

func mapUrls() {

	router.Use(logger.New())
	router.Static("/images", "./static/images")

	api := router.Group("/api/v1")
	api.Post("/login", user_controller.Login)
	api.Get("/ping", ping_controller.Ping)

	apiAuth := router.Group("/api/v1")
	apiAuth.Use(middleware.AuthMiddleware)
	apiAuth.Get("/users/:user_id", user_controller.Get)
	apiAuth.Get("/profile", user_controller.GetProfile)
	apiAuth.Get("/users", user_controller.Find)
	apiAuth.Post("/users", user_controller.Insert)
	apiAuth.Post("/avatar", user_controller.UploadImage)
	apiAuth.Post("/profile/change-password", user_controller.ChangePassword)

	apiAuthAdmin := router.Group("/api/v1/admin")
	apiAuthAdmin.Use(middleware.AuthAdminMiddleware)
	apiAuthAdmin.Put("/users/:user_email", user_controller.Edit)
	apiAuthAdmin.Delete("/users/:user_email", user_controller.Delete)
	apiAuthAdmin.Get("/users/:user_email/reset-password", user_controller.ResetPassword)

}
