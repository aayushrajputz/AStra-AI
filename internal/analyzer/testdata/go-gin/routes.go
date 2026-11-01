package main

import (
	"github.com/gin-gonic/gin"
	"example.com/ginapp/handlers"
)

func routes() {
	router := gin.Default()
	v1 := router.Group("/v1")
	controller := handlers.UsersController{}
	v1.GET("/users/:id", controller.GetUser)
	v1.POST("/users", handlers.CreateUser)
}
