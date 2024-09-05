package utils

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v64/github"
)

func AccessResourceViaRest(url string, token string) (string, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header = http.Header{
		"Accept":        {"application/vnd.github+json"},
		"Authorization": {fmt.Sprintf("Bearer %s", token)},
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ValidateSignature validates the GitHub webhook signature
func ValidateSignature(body []byte, signatureHeader string, secret string) bool {
	if signatureHeader == "" || len(signatureHeader) < 7 {
		return false
	}
	computedHash := hmac.New(sha256.New, []byte(secret))
	computedHash.Write(body)
	expectedSig := hex.EncodeToString(computedHash.Sum(nil))
	return hmac.Equal([]byte(expectedSig), []byte(signatureHeader[7:]))
}

func GetAppInstallationToken(keyPath string, appID int64, installationID int64) (*github.InstallationToken, *github.Response, error) {
	itr, err := ghinstallation.NewKeyFromFile(http.DefaultTransport, appID, installationID, string(keyPath))
	if err != nil {
		return nil, nil, err
	}

	// Can successfully get access token
	ctx := context.Background()
	_, err = itr.Token(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Auth with app creds - this should work.
	atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, appID, keyPath)
	if err != nil {
		return nil, nil, err
	}
	client := github.NewClient(&http.Client{Transport: atr})
	return client.Apps.CreateInstallationToken(ctx, installationID, nil)

}
