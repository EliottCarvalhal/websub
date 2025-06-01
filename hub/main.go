package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/mux"
)

const defaultPort = "8080"

var (
	subs  = make(map[string]*Subscriber)
	mutex sync.RWMutex
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", postHandler).Methods("POST")
	r.HandleFunc("/publish", publishHandler).Methods("POST")

	fmt.Printf("Starting server on port %s...\n", defaultPort)
	log.Fatal(http.ListenAndServe(":"+defaultPort, r))

}

type Subscriber struct {
	Callback string
	Topic    string
	Secret   string
}

type JSONResp struct {
	Data string
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	params := r.Form

	mode := params.Get("hub.mode")
	callback := params.Get("hub.callback")
	topic := params.Get("hub.topic")
	secret := params.Get("hub.secret")

	if mode == "" || callback == "" || topic == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// if requesting unsubscribe, we check they're a subscriber before removing them from the map
	if mode == "unsubscribe" {
		fmt.Println("unsubscribing...")

		mutex.Lock()
		cb, ok := subs[callback]
		mutex.Unlock()

		if !ok {
			http.Error(w, "cannot unsubscribe without being a subscriber", http.StatusBadRequest)
			return
		}

		valid := verifyIntent(callback, mode, topic, secret, w)

		if !valid {
			return
		}

		mutex.Lock()
		delete(subs, cb.Callback)
		mutex.Unlock()

		w.WriteHeader(http.StatusNoContent)
		return

	} else if mode != "subscribe" { //unexpected mode
		http.Error(w, "unsupported hub mode", http.StatusBadRequest)
		return
	}

	valid := verifyIntent(callback, mode, topic, secret, w)
	if !valid {
		return
	}

	// add to map
	mutex.Lock()
	subs[callback] = &Subscriber{
		Callback: callback,
		Topic:    topic,
		Secret:   secret,
	}
	mutex.Unlock()

	w.WriteHeader(http.StatusOK)
}

func verifyIntent(callback, mode, topic, challenge string, w http.ResponseWriter) bool {
	q := fmt.Sprintf("%s?hub.mode=%s&hub.topic=%s&hub.challenge=%s", callback, mode, topic, challenge)

	callbackURL, err := url.Parse(q)
	if err != nil {
		http.Error(w, "invalid callback URL", http.StatusBadRequest)
		return false
	}

	// GET to callback URL to verify client secret
	resp, err := http.DefaultClient.Do(&http.Request{
		Method: http.MethodGet,
		URL:    callbackURL,
	})
	if err != nil {
		http.Error(w, "failed to call callback url", http.StatusBadRequest)
		return false
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Callback verification failed with status: %d %s\n", resp.StatusCode, string(bodyBytes))
		http.Error(w, "callback verification failed", http.StatusBadRequest)
		return false
	}

	if string(bodyBytes) != challenge {
		http.Error(w, "challenge did not match", http.StatusUnauthorized)
		return false
	}

	fmt.Println("verification complete", challenge)

	return true
}

func publishHandler(w http.ResponseWriter, r *http.Request) {
	msg := &JSONResp{Data: "new data"}
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		http.Error(w, "failed to marshal json", http.StatusInternalServerError)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for cb, sub := range subs {
		sig := hmac.New(sha256.New, []byte(sub.Secret))
		sig.Write(jsonBody)
		sigHex := fmt.Sprintf("%x", sig.Sum(nil))

		req, _ := http.NewRequest("POST", cb, bytes.NewReader(jsonBody))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-Hub-Signature", "sha256="+sigHex)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("Failed to post to %s: %v", cb, err)
			continue
		}

		resp.Body.Close()
		log.Printf("Published to %s with status %d", cb, resp.StatusCode)
	}
}
