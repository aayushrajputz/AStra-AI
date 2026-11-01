package main

import (
	"github.com/go-chi/chi/v5"
	"example.com/chiapp/handlers"
)

func routes() {
	router := chi.NewRouter()
	router.Route("/api", func(api chi.Router) {
		api.Get("/users", handlers.ListUsers)
		api.Post("/users", handlers.CreateUser)
	})
}
