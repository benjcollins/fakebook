package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/gob"
	"os"
)

type User struct {
	Name string
	Username string
	Password []byte
	Email string
	Age int
	Bio string
	Picture []byte
}

func (user User) save() {
	file, err := os.Create("users/" + user.Username + ".user")
	if err != nil {
		panic(err)
	}
	encoder := gob.NewEncoder(file)
	encoder.Encode(user)
	file.Close()
}

func (user *User) load() bool {
	file, err := os.Open("users/" + user.Username + ".user")

	if err != nil {
		return false
	}

	gob.NewDecoder(file).Decode(user)
	return true
}

func (user User) auth(password string) bool {
	hash := sha1.New()
	hash.Write([]byte(password))
	return bytes.Equal(hash.Sum(nil), user.Password)
}

func (user User) avaliable() bool {
	_, err := os.Stat("users/" + user.Username + ".user")
	return os.IsNotExist(err)
}