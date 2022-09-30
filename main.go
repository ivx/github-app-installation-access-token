package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dvsekhvalnov/jose2go"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
)

type permissions struct {
	Contents string `json:"contents"`
	MetaData string `json:"metadata"`
}

type body struct {
	Token                string      `json:"token"`
	ExpiresAt            string      `json:"expires_at"`
	Permissions          permissions `json:"permissions"`
	RepositorySelections string      `json:"repository_selections"`
}

func fetchToken(installationId string, jwt string) string {
	httpposturl := "https://api.github.com/app/installations/" + installationId + "/access_tokens"

	request, err := http.NewRequest("POST", httpposturl, nil)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	res := body{}
	json.Unmarshal(responseBody, &res)

	return res.Token
}

func toUnixString(time time.Time) string {
	return strconv.FormatInt(time.Unix(), 10)
}

func createJwtJose(appId string, key string) string {
	iat := toUnixString(time.Now().Add(time.Second * -30))
	exp := toUnixString(time.Now().Add(time.Second * 30))

	payload := "{\"iat\":" + iat + ",\"exp\":" + exp + ",\"iss\":\"" + appId + "\"}"

	privateKey, err := Rsa.ReadPrivate([]byte(key))
	if err != nil {
		panic(err)
	}

	token, err := jose.Sign(payload, jose.RS256, privateKey)
	if err != nil {
		panic(err)
	}

	return token
}

func getEnvs() (string, string, string) {
	installationId, ok := os.LookupEnv("INSTALLATION_ID")
	if !ok {
		panic("INSTALLATION_ID not set")
	}
	appId, ok := os.LookupEnv("APP_ID")
	if !ok {
		panic("APP_ID not set")
	}
	privateKey, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		panic("PRIVATE_KEY not set")
	}

	return installationId, appId, strings.Replace(privateKey, "\\n", "\n", -1)
}

func main() {
	installationId, appId, privateKey := getEnvs()

	token := createJwtJose(appId, privateKey)
	fmt.Print(fetchToken(installationId, token))
}
