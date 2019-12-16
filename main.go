package main

import (
	"unicode"
	"github.com/gorilla/mux"
	"io/ioutil"
	"strconv"
	"fmt"
	"net/url"
	"time"
	"encoding/base64"
	"crypto/rand"
	"net/http"
	"html/template"
	"crypto/sha1"
)

type userHandlerFunc func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse)
type targetUserHandlerFunc func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse, targetUser User)

type tokenResponse struct {
	Token string
}

type errorResponse struct {
	tokenResponse
	IsError bool
	Message string
}

type loginResponse struct {
	errorResponse
	Username string
	Password string
}

type createAccountResponse struct {
	errorResponse
	Name, Username, Password, RPassword string
}

type profileResponse struct {
	tokenResponse
	User User
}

func (res *errorResponse) Throw(message string) {
	res.IsError = true
	res.Message = message
}

type server struct {
	tokens map[string]token
}

type token struct {
	username string
	expires time.Time
}

func (server *server) generateToken(user *User) string {
	for key, token := range server.tokens {
		if token.username == user.Username {
			delete(server.tokens, key)
		}
	}

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	tokenID := url.PathEscape(base64.StdEncoding.EncodeToString(b))

	server.tokens[tokenID] = token{
		username: user.Username,
		expires: time.Now().AddDate(0, 0, 1),
	}
	
	return tokenID
}

func (server *server) handleLogin() http.HandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/login.html"))

	return func(w http.ResponseWriter, req *http.Request) {

		if req.Method == "GET" {
			page.Execute(w, loginResponse{})
			return
		}

		username := req.FormValue("username")
		password := req.FormValue("password")

		res := loginResponse{errorResponse{}, username, password}

		user := &User{Username: username}
		if !user.load() || !user.auth(password) {
			res.Throw("Incorrect username or password!")
			page.Execute(w, res)
			return
		}

		token := server.generateToken(user)

		http.Redirect(w, req, "/" + token + "/self/profile.html", http.StatusFound)
	}
}

func (server *server) handleCreateAccount() http.HandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/create-account.html"))
	picture, err := ioutil.ReadFile("images/default.png")
	hash := sha1.New()

	return func(w http.ResponseWriter, req *http.Request) {

		if req.Method == "GET" {
			page.Execute(w, createAccountResponse{})
			return
		}

		name := req.FormValue("name")
		username := req.FormValue("username")
		password := req.FormValue("password")
		rpassword := req.FormValue("rpassword")

		res := createAccountResponse{
			errorResponse{},
			name,
			username,
			password,
			rpassword,
		}

		if name == "" {
			res.Throw("Name field cannot be empty!")
			page.Execute(w, res)
			return	
		}
		if username == "" {
			res.Throw("Username field cannot be empty!")
			page.Execute(w, res)
			return
		}
		for _, ch := range username {
			if !unicode.IsDigit(ch) && !unicode.IsLetter(ch) {
				res.Throw("Username can only contain letters and numbers!")
				page.Execute(w, res)
				return
			}
		}
		if !(User{Username: username}).avaliable() {
			count := 1
			for !(User{Username: username + strconv.Itoa(count)}).avaliable() {
				count++
			}
			res.Throw("This username is already taken!")
			res.Username = username + strconv.Itoa(count)
			page.Execute(w, res)
			return
		}
		if password != rpassword {
			res.Throw("Passwords do not match!")
			res.RPassword = ""
			page.Execute(w, res)
			return
		}
		if len(password) < 10 {
			res.Throw("Password must be at least 10 characters")
			res.Password = ""
			res.RPassword = ""
			page.Execute(w, res)
			return
		}

		hash.Reset()
		hash.Write([]byte(password))
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

func (server *server) handleProfile() targetUserHandlerFunc {
	editProfilePage := template.Must(template.ParseFiles("html/layout.html", "html/edit-profile.html"))
	profilePage := template.Must(template.ParseFiles("html/layout.html", "html/profile.html"))

	return func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse, targetUser User) {

		if req.Method == "GET" {
			res := profileResponse{token, targetUser}
			if user.Username == targetUser.Username {
				editProfilePage.Execute(w, res)
				return
			}
			profilePage.Execute(w, res)
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
			res := profileResponse{token, user}
			editProfilePage.Execute(w, res)
		}
	}
}

func (server *server) handleImage() targetUserHandlerFunc {
	return func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse, targetUser User) {
		vars := mux.Vars(req)
		if vars["name"] == "profile" {
			w.Write(targetUser.Picture)
		}
	}
}

func (server *server) handleNewPost() userHandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/new-post.html"))
	return func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse) {
		if req.Method == "GET" {
			page.Execute(w, token)
			return
		}
	}	
}

func (server *server) validateUser(handler userHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		token := vars["token"]

		if tokenData, ok := server.tokens[token]; ok {
			if tokenData.expires.After(time.Now()) {
				user := User{Username: tokenData.username}
				user.load()
				handler(w, req, user, tokenResponse{token})
				return
			}
		}

		http.Redirect(w, req, "/login.html", http.StatusFound)
	}
}

func (server *server) getTargetUser(handler targetUserHandlerFunc) userHandlerFunc {
	page := template.Must(template.ParseFiles("html/layout.html", "html/doesnt-exist.html"))
	return func(w http.ResponseWriter, req *http.Request, user User, token tokenResponse) {
		vars := mux.Vars(req)
		username := vars["username"]
		if username == "self" {
			handler(w, req, user, token, user)
			return
		}
		targetUser := User{Username: username}
		if !targetUser.load() {
			page.Execute(w, targetUser.Username)
			return
		}
		handler(w, req, user, token, targetUser)
	}
}

func main() {
	server := &server{tokens: make(map[string]token)}
	router := mux.NewRouter()
	router.HandleFunc("/login.html", server.handleLogin())
	router.HandleFunc("/create-account.html", server.handleCreateAccount())
	router.HandleFunc("/{token}/{username}/profile.html", server.validateUser(server.getTargetUser(server.handleProfile())))
	router.HandleFunc("/{token}/{username}/{name}.png", server.validateUser(server.getTargetUser(server.handleImage())))
	router.HandleFunc("/{token}/new-post.html", server.validateUser(server.handleNewPost()))

	fmt.Println("Started!")

	http.ListenAndServeTLS(":443", "https-server.crt", "https-server.key", router)
}