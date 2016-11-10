package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

var l = logrus.New()

var (
	EnvPortName = "PORT"
	EnvPort     string

	// oauth client params
	// for the poc we most likely use the single root client both for the oauth app and the idp
	EnvHydraClientIDName = "CLIENTID"
	EnvHydraClientID     string
)

//
type User struct {
	Name string
	Pass string
}

//
func getEnv() {
	EnvPort = os.Getenv(EnvPortName)

	if EnvPort == "" {
		l.Fatal("Need env var ", EnvPortName)
	}
}

//
func main() {
	getEnv()

	r := mux.NewRouter()
	r.HandleFunc("/auth", LoginHandler).Methods("GET")
	r.HandleFunc("/auth", LoginHandlerSubmit).Methods("POST")
	r.HandleFunc("/consent", ConsentHandler).Methods("GET")
	r.HandleFunc("/consent", ConsentHandlerSubmit).Methods("POST")

	l.Infof("start listen on port: %s", EnvPort)
	l.Fatal(http.ListenAndServeTLS("localhost:"+EnvPort, "cert.pem", "key.pem", r))
}

// accept an auth challenge from hydra; render login;
// step 2 of the flow
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")

	l.Infof("GET /auth, challenge: %s", challenge)

	//TODO in production, validate the signature with hydra.consent.challenge/public
	parsed, err := parseChallenge(challenge)
	if err != nil {
		l.Errorf("can't parse challenge: %v", err)
		renderErr(err, w)
	} else {
		l.Info("parsed challenge: %v", parsed)
	}

	if err := renderTemplate("login.tpl", w, nil); err != nil {
		renderErr(err, w)
	}
}

// accept and verify credentials, send consent token to hydra - step 3 of the flow
func LoginHandlerSubmit(w http.ResponseWriter, r *http.Request) {
	l.Infof("POST /auth")
	err := r.ParseForm()
	if err != nil {
		renderErr(err, w)
	}

	var user User

	decoder := schema.NewDecoder()
	err = decoder.Decode(user, r.PostForm)

	a, err := Authenticate(user.Name, user.Pass)

	if err != nil {
		renderErr(err, w)
	} else {
		if !a {
			l.Warn("user not authenticated")
		} else {
			//redir to consent screen
			l.Info("user authenticated, redirecting to consent screen")
			http.Redirect(w, r, "/consent", 302)
		}
	}
}

func ConsentHandler(w http.ResponseWriter, r *http.Request) {
	if err := renderTemplate("consent.tpl", w, nil); err != nil {
		renderErr(err, w)
	}
}

func ConsentHandlerSubmit(w http.ResponseWriter, r *http.Request) {
	/*
		https://hydra.myapp.com/oauth2/auth?client_id=c3b49cf0-88e4-4faa-9489-28d5b8957858&response_type=code&scope=core+hydra&state=vboeidlizlxrywkwlsgeggff&nonce=tedgziijemvninkuotcuuiof&consent=eyJhbGciOiJSU...
	*/
}

//
func renderTemplate(name string, w http.ResponseWriter, ctx interface{}) error {
	cwd, _ := os.Getwd()

	t := template.New("login.tpl")
	t, err := t.ParseFiles(filepath.Join(cwd, "views", name))
	if err != nil {
		return err
	}

	err = t.Execute(w, nil)
	if err != nil {
		return err
	}

	return nil
}

//
func renderErr(err error, w http.ResponseWriter) {
	l.Error(err)
	w.WriteHeader(500)
}

// user authenticated ok - send consent token back to hydra
func redirToHydra(w http.ResponseWriter) {
}

// parses the challenge JWT obained from hydra
// returns a map of claims:
// - redir
func parseChallenge(c string) (map[string]string, error) {
	token, err := jwt.Parse(c, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method: " + token.Method.Alg())
		}
		//load the pem pubkey!
		key, err := loadPubKey("crypto/hydra.consent.challenge.public.pem")
		if err != nil {
			return nil, errors.New("can't load key: " + err.Error())
		}

		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("Token invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, errors.New("Can't parse claims")
	}

	ret := map[string]string{"redir": ""}

	for k, _ := range ret {
		if val, ok := claims["redir"].(string); ok {
			ret[k] = val
		} else {
			return nil, errors.New("Can't parse claims")
		}
	}

	return ret, nil
}

func loadPubKey(path string) (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func getChallengeField(t jwt.Token, claim string) {
}
