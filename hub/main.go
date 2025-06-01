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

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const defaultPort = "8080"

var (
	// callback -> topic
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

	// UUID that requester needs to echo for verification
	secret := uuid.New().String()

	// if requesting unsubscribe, we check they're a subscriber before removing them from the map
	if params.Get("hub.mode") == "unsubscribe" {
		fmt.Println("unsubscribing...")
		mutex.Lock()
		defer mutex.Unlock()

		cb, ok := subs[params.Get("hub.callback")]
		if !ok {
			http.Error(w, "cannot unsubscribe without being a subscriber", http.StatusBadRequest)
			return
		}

		valid := verifyIntent(params.Get("hub.callback"), params.Get("hub.mode"), params.Get("hub.topic"), secret, w)

		if valid {
			delete(subs, cb.Callback)
		}

		return

	} else if params.Get("hub.mode") != "subscribe" { //unexpected mode
		http.Error(w, "unsupported hub mode", http.StatusBadRequest)
		return
	}

	valid := verifyIntent(params.Get("hub.callback"), params.Get("hub.mode"), params.Get("hub.topic"), secret, w)
	if !valid {
		return
	}

	// add to map
	mutex.Lock()
	subs[params.Get("hub.callback")] = &Subscriber{
		Callback: params.Get("hub.callback"),
		Topic:    params.Get("hub.topic"),
		Secret:   params.Get("hub.secret"),
	}
	mutex.Unlock()

	hubBody := &JSONResp{Data: "hello"}
	jsonBody, err := json.Marshal(hubBody)
	if err != nil {
		http.Error(w, "failed to marshal body", http.StatusInternalServerError)
		return
	}

	sig := hmac.New(sha256.New, []byte(params.Get("hub.secret")))
	sig.Write(jsonBody)
	sigHex := fmt.Sprintf("%x", sig.Sum(nil))

	h := http.Header{}
	h.Add("Content-Type", "application/json")
	h.Add("X-Hub-Signature", "sha256="+sigHex)

	callbackURL, err := url.Parse(params.Get("hub.callback"))
	if err != nil {
		http.Error(w, "invalid callback URL", http.StatusBadRequest)
		return
	}

	_, err = http.DefaultClient.Do(&http.Request{
		Method: http.MethodPost,
		URL:    callbackURL,
		Header: h,
		Body:   io.NopCloser(bytes.NewReader(jsonBody)),
	})

	if err != nil {
		http.Error(w, "failed to call callback url", http.StatusBadRequest)
		return
	}

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
