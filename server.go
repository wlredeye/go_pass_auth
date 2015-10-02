package main

import (
	"fmt"

	"net/http"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/trusch/httpauth"
	"golang.org/x/crypto/bcrypt"
)

var (
	backend     httpauth.SqlAuthBackend
	aaa         httpauth.Authorizer
	roles       map[string]httpauth.Role
	port        = 8009
)

func main() {
	var err error

	// create the backend
	datasource := "root:root@/test"
	backend, err = httpauth.NewSqlAuthBackend("mysql", datasource)
	if err != nil {
		panic(err)
	}

	// create some default roles
	roles = make(map[string]httpauth.Role)
	roles["user"] = 30
	roles["admin"] = 80
	aaa, err = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"), "user", roles)

	// create a default user
	hash, err := bcrypt.GenerateFromPassword([]byte("adminadmin"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	defaultUser := httpauth.UserData{Username: "admin", Email: "admin@localhost", Hash: hash, Role: "admin"}
	err = backend.SaveUser(defaultUser)
	if err != nil {
		panic(err)
	}

	// set up routers and route handlers
	r := mux.NewRouter()
	r.HandleFunc("/login", getLogin).Methods("GET")
	r.HandleFunc("/register", postRegister).Methods("POST")
	r.HandleFunc("/login", postLogin).Methods("POST")
	r.HandleFunc("/admin", handleAdmin).Methods("GET")
	r.HandleFunc("/add_user", postAddUser).Methods("POST")
	r.HandleFunc("/change", postChange).Methods("POST")
	r.HandleFunc("/", handlePage).Methods("GET") // authorized page
	r.HandleFunc("/logout", handleLogout)

	http.Handle("/", r)
	fmt.Printf("Server running on port %d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
