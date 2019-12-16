package main

import (
	"github.com/gorilla/mux"
	"io/ioutil"
	"strconv"
	"fmt"
	"net/url"
	"time"
	"encoding/base64"
	"crypto/rand"
	"encoding/gob"
	"net/http"
	"html/template"
	"os"
	"regexp"
	"bytes"
	"crypto/sha1"
)

type UserHandlerFunc func(w http.ResponseWriter, req *http.Request, user User)
type TargetUserHandlerFunc func(w http.ResponseWriter, req *http.Request, user User, targetUser User)

type User struct {
	Name string
	Username string
	Password []byte
	Email string
	Age int
	Bio string
	Picture []byte
}

type Response struct {
	Token string
	IsError bool
	Message string
	Name string
	Username string
	Password string
	RPassword string
	User User
}

type Server struct {
	tokens map[string]Token
}

type Token struct {
	username string
	expires time.Time
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

func (server *Server) handleLogin() http.HandlerFunc {
	r, _ := regexp.Compile("[^a-zA-Z0-9\\.\\-]")
	page := template.Must(template.ParseFiles("html/layout.html", "html/login.html"))

	return func(w http.ResponseWriter, req *http.Request) {

		if req.Method == "GET" {
			page.Execute(w, Response{IsError: false})
			return
		}

		username := r.ReplaceAllString(req.FormValue("username"), "_")
		password := req.FormValue("password")

		response := Response{
			IsError: false,
			Username: username,
			Password: password,
		}

		user := &User{Username: username}
		if !user.load() {
			response.IsError = true
			response.Message = "Incorrect username or password!"
		}

		hash := sha1.New()
		hash.Write([]byte(password))
		if !bytes.Equal(hash.Sum(nil), user.Password) {
			response.IsError = true
			response.Message = "Incorrect username or password!"
		}

		if response.IsError {
			page.Execute(w, response)
			return
		}

		for key, token := range server.tokens {
			if token.username == username {
				delete(server.tokens, key)
			}
		}

		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			panic(err)
		}

		token := url.PathEscape(base64.StdEncoding.EncodeToString(b))
		
		server.tokens[token] = Token{
			username: username,
			expires: time.Now().AddDate(0, 0, 1),
		}

		http.Redirect(w, req, "/" + token + "/self/profile.html", http.StatusFound)
	}
}

func (server *Server) handleCreateAccount() http.HandlerFunc {
	r, _ := regexp.Compile("[^a-zA-Z0-9\\.\\-]")
	page := template.Must(template.ParseFiles("html/layout.html", "html/create-account.html"))

	return func(w http.ResponseWriter, req *http.Request) {

		if req.Method == "GET" {
			page.Execute(w, Response{IsError: false})
			return
		}

		name := req.FormValue("name")
		username := r.ReplaceAllString(req.FormValue("username"), "_")
		password := req.FormValue("password")
		rpassword := req.FormValue("rpassword")

		response := Response{
			IsError: false,
			Name: name,
			Username: username,
			Password: password,
			RPassword: rpassword,
		}

		if name == "" {
			response.IsError = true
			response.Message = "Name field cannot be empty!"
		} else if username == "" {
			response.IsError = true
			response.Message = "Username field cannot be empty!"
		} else if _, e := os.Stat("users/" + username + ".user"); !os.IsNotExist(e) {
			response.IsError = true
			response.Message = "This username is already taken!"
			response.Username = ""
		} else if password != rpassword {
			response.IsError = true
			response.Message = "Passwords do not match!"
			response.RPassword = ""
		} else if len(password) < 10 {
			response.IsError = true
			response.Message = "Password must be at least 10 characters"
			response.Password = ""
			response.RPassword = ""
		}

		if response.IsError {
			page.Execute(w, response)
			return
		}

		hash := sha1.New()
		hash.Write([]byte(password))
		picture, err := ioutil.ReadFile("images/default.png")
		if err != nil {
			panic(err)
		}
		user := User{
			Name: name,
			Username: username,
			Password: hash.Sum(nil),
			Bio: "Hello, I am using the fakebook!",
			Picture: picture,
		}
		user.save()
		http.Redirect(w, req, "/login.html", http.StatusFound)
	}
}

func (server *Server) handleProfile() TargetUserHandlerFunc {
	editProfilePage := template.Must(template.ParseFiles("html/layout.html", "html/edit-profile.html"))
	profilePage := template.Must(template.ParseFiles("html/layout.html", "html/profile.html"))
	return func(w http.ResponseWriter, req *http.Request, user User, targetUser User) {
		vars := mux.Vars(req)

		if req.Method == "GET" {
			response := Response{Token: vars["token"], User: targetUser}
			if user.Username == targetUser.Username {
				editProfilePage.Execute(w, response)
				return
			}
			profilePage.Execute(w, response)
			return
		}

		if user.Username == targetUser.Username {

			name := req.FormValue("name")
			age := req.FormValue("age")
			email := req.FormValue("email")
			bio := req.FormValue("bio")
			file, _, err := req.FormFile("picture")

			if err == nil {
				data, err := ioutil.ReadAll(file)
				user.Picture = data
				if err != nil {
					panic(err)
				}
			}

			if name != "" {
				user.Name = name
			}
			user.Age, _ = strconv.Atoi(age)
			user.Email = email
			user.Bio = bio

			user.save()
			response := Response{Token: vars["token"], User: user}
			editProfilePage.Execute(w, response)
		}
	}
}

func (server *Server) handleImage() TargetUserHandlerFunc {
	return func(w http.ResponseWriter, req *http.Request, user User, targetUser User) {
		vars := mux.Vars(req)
		if vars["name"] == "profile" {
			w.Write(targetUser.Picture)
		}
	}
}

func (server *Server) handleNewPost() UserHandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/new-post.html"))
	return func(w http.ResponseWriter, req *http.Request, user User) {
		vars := mux.Vars(req)
		if req.Method == "GET" {
			page.Execute(w, Response{Token: vars["token"]})
			return
		}
	}	
}

func (server *Server) validateUser(handler func(w http.ResponseWriter, req *http.Request, user User)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		token := vars["token"]

		if token, ok := server.tokens[token]; ok {
			if token.expires.After(time.Now()) {
				user := User{Username: token.username}
				user.load()
				handler(w, req, user)
				return
			}
		}

		http.Redirect(w, req, "/login.html", http.StatusFound)
	}
}

func (server *Server) getTargetUser(handler TargetUserHandlerFunc) UserHandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/doesnt-exist.html"))
	return func(w http.ResponseWriter, req *http.Request, user User) {
		vars := mux.Vars(req)
		if vars["username"] == "self" {
			handler(w, req, user, user)
			return
		}
		targetUser := User{Username: vars["username"]}
		if !targetUser.load() {
			page.Execute(w, targetUser.Username)
			return
		}
		handler(w, req, user, targetUser)
	}
}

func main() {
	server := &Server{tokens: make(map[string]Token)}
	router := mux.NewRouter()
	router.HandleFunc("/login.html", server.handleLogin())
	router.HandleFunc("/create-account.html", server.handleCreateAccount())
	router.HandleFunc("/{token}/{username}/profile.html", server.validateUser(server.getTargetUser(server.handleProfile())))
	router.HandleFunc("/{token}/{username}/{name}.png", server.validateUser(server.getTargetUser(server.handleImage())))
	router.HandleFunc("/{token}/new-post.html", server.validateUser(server.handleNewPost()))

	fmt.Println("Started!")

	http.ListenAndServeTLS(":443", "https-server.crt", "https-server.key", router)
}