package handlers

import "example.com/chiapp/service"
import "net/http"

func ListUsers(w http.ResponseWriter, r *http.Request) {
	service.LoadUsers()
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	service.CreateUser()
}
