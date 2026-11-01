package handlers

import "example.com/echoapp/service"
import "github.com/labstack/echo/v4"

func GetUser(c echo.Context) error {
	service.FetchUser()
	return nil
}

func CreateUser(c echo.Context) error {
	service.StoreUser()
	return nil
}
