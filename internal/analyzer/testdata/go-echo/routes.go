package main

import (
	"github.com/labstack/echo/v4"
	"example.com/echoapp/handlers"
)

func routes() {
	server := echo.New()
	v1 := server.Group("/v1")
	v1.GET("/users/:id", handlers.GetUser)
	v1.POST("/users", handlers.CreateUser)
}
