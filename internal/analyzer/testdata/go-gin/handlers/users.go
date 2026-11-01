package handlers

import "example.com/ginapp/service"
import "github.com/gin-gonic/gin"

type CreateUserRequest struct {
	Alias string `json:"alias,omitempty"`
}

type UsersController struct{}

func (controller *UsersController) GetUser() {
	service.FetchUser()
}

func CreateUser(c *gin.Context) {
	var request CreateUserRequest
	c.ShouldBindJSON(&request)
	service.StoreUser()
}
