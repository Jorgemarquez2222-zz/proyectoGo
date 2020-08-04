package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"

	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

type User struct {
	gorm.Model
	id              int
	User            string
	Pass            string
	Tipo            string
	createdAt       time.Time
	updatedAt       time.Time
	time_registered time.Time
}

var (
	users = []string{"Joe", "Veer", "Zion"}
)

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Throws unauthorized error
	if username != "jon" || password != "shhh!" {
		return echo.ErrUnauthorized
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		"Jon Snow",
		true,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func getUsers(c echo.Context) error {
	//var myEnv map[string]string

	userDb := os.Getenv("USER_BD")
	passDb := os.Getenv("PASS_BD")
	hostDB := os.Getenv("HOST_DDBB")
	nameDb := os.Getenv("NAME_DDBB")

	fmt.Println(userDb)
	stringConnectionDDBB := userDb + ":" + passDb + "@(" + hostDB + ")/" + nameDb + "?charset=utf8&parseTime=True&loc=Local"
	db, _ := gorm.Open(
		"mysql",
		stringConnectionDDBB,
	)
	user := &User{}
	db.Table("user").Select("user, pass, tipo").Where("user = ?", "bot02").Scan(&user)

	return c.JSON(http.StatusOK, user)
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// CORS default
	// Allows requests from any origin wth GET, HEAD, PUT, POST or DELETE method.
	// e.Use(middleware.CORS())

	// CORS restricted
	// Allows requests from any `https://labstack.com` or `https://labstack.net` origin
	// wth GET, PUT, POST or DELETE method.
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:4200", "http://localhost:4200"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))

	// Login route
	e.POST("/login", login)
	e.GET("/api/users", getUsers)

	// Unauthenticated route

	// Restricted group
	r := e.Group("/api")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}
	r.Use(middleware.JWTWithConfig(config))
	r.GET("/login", restricted)
	r.GET("/accesible", accessible)

	e.Logger.Fatal(e.Start(":1323"))

}
