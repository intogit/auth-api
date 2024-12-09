package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	sessionToken   string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	fmt.Println("hiii auth service started")
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/signin", signin)
	http.HandleFunc("/signout", signout)
	http.HandleFunc("/home", home)
	http.ListenAndServe(":8080", nil)
	// log.Fatal(http.ListenAndServe(":8080", nil))
	fmt.Print("server connection success")
}

func signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid method", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(w, "Password must be more than 8 character", er)
		return
	}
	if _, ok := users[username]; ok {
		er := http.StatusConflict
		http.Error(w, "User already exist", er)
		return
	}
	hashedPassword, _ := HashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}
	fmt.Fprintln(w, "user created successfully!")
}
func signin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "method not allowed", er)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !ValidateHashPassword(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "user do not exist or password do not match", er)
		return
	}

	sessionToken := GenerateToken(32)
	csrfToken := GenerateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: 1, // even this protect from csrf but its accuracy is 95%
		// HttpOnly: true,
		Secure: true, // so that i can pass the csrf token in header
	})

	user.sessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	w.Header().Set("X-CSRF-Token", csrfToken)
	fmt.Fprintln(w, "user logged in successfully!")
}
func home(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "method not allowed", er)
		return
	}

	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	reqCookieSessionToken, err := r.Cookie("session_token")
	if err != nil {
		fmt.Printf("Error: Cant find cookie :/\r\n")
		return
	}
	if users[username].sessionToken != string(reqCookieSessionToken.Value) {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken != user.CSRFToken {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	fmt.Fprintln(w, "user navigated to home successfully!")
}
func signout(w http.ResponseWriter, r *http.Request) {
	//authorizer starts
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	reqCookieSessionToken, err := r.Cookie("session_token")
	if err != nil {
		fmt.Printf("Error: Cant find cookie :/\r\n")
		return
	}
	if users[username].sessionToken != string(reqCookieSessionToken.Value) {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken != user.CSRFToken {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	// authorizer ends
	// ginuine user:

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		SameSite: 1, // even this protect from csrf but its accuracy is 95%
		// HttpOnly: true,
		Secure: true, // so that i can pass the csrf token in header
	})
	w.Header().Set("X-CSRF-Token", "")
	user.sessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "user logged out successfully")
}
