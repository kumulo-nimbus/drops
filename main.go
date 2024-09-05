package main

import (
	"drops/pkg/utils"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	fmt.Print("service listen on port:3000")
	r := mux.NewRouter()
	r.HandleFunc("/", onWebhook)
	r.Use(webhookMsgMiddleware)
	srv := &http.Server{
		Addr: ":3000",
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}

func onWebhook(w http.ResponseWriter, req *http.Request) {
	webHookBody, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Print(string(webHookBody))
	secret := os.Getenv("SECRET")
	signatureHeader := req.Header.Get("X-Hub-Signature-256")
	if !utils.ValidateSignature(webHookBody, signatureHeader, secret) {
		fmt.Print("event signature is not valid")
	}
	appID := os.Getenv("APP_ID")
	appid, err := strconv.Atoi(appID)
	if err != nil {
		return
	}
	installtionID := os.Getenv("INSTALLTION_ID")
	iid, err := strconv.Atoi(installtionID)
	if err != nil {
		return
	}
	pemFilePath := os.Getenv("PRIVATE_KEY_PATH")
	ittt, resp, err := utils.GetAppInstallationToken(pemFilePath, int64(appid), int64(iid))
	if err != nil {
		return
	}
	if resp.StatusCode >= 300 {
		return
	}
	url := "https://api.github.com/repos/kumulo-nimbus/drops/issues"

	token :=  .GetToken()
	resource, err := utils.AccessResourceViaRest(url, token)
	if err != nil {
		return
	}
	fmt.Print(resource)
}

func webhookMsgMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// validate hook
		next.ServeHTTP(w, r)
	})
}
