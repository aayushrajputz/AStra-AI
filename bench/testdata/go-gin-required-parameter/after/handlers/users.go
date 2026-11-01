package handlers

import "example.com/benchapp/service"

func GetUser() {
	service.FetchUser()
}

func Health() {}
