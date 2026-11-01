package main

import (
	"github.com/gin-gonic/gin"
	"example.com/benchapp/handlers"
)

func routes() {
	router := gin.Default()
	router.GET("/users/:id", handlers.GetUser)
	router.GET("/health", handlers.Health)
}
