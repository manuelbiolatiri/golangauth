package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/manuelbiolatiri/golangauthtest/controllers"
)

func UsersRoute(route fiber.Router) {
	route.Post("/signup", controllers.SignUp)
	route.Post("/login", controllers.Login)
}
