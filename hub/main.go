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
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const defaultPort = "8080"

var (
	subs  = make(map[SubscriberKey]*Subscriber)
	mutex sync.RWMutex
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", postHandler).Methods("POST")
	r.HandleFunc("/publish", publishHandler).Methods("POST")

	log.Printf("Starting server on port %s...\n", defaultPort)
	log.Fatal(http.ListenAndServe(":"+defaultPort, r))

}

type SubscriberKey struct {
	Callback string
	Topic    string
}

type Subscriber struct {
	Callback string
	Topic    string
	Secret   string
	Expires  time.Time
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
	prefLease := params.Get("hub.lease")

	if mode == "" || callback == "" || topic == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	if mode != "subscribe" && mode != "unsubscribe" {
		http.Error(w, "unrecognized mode", http.StatusBadRequest)
		return
	}

	// if client provided lease use theirs, otherwise default to 10 minutes
	var leaseSeconds int
	if prefLease != "" {
		leaseSeconds, err = strconv.Atoi(prefLease)
		if err != nil || leaseSeconds <= 0 {
			http.Error(w, "Invalid hub.lease value", http.StatusBadRequest)
			return
		}
	} else {
		leaseSeconds = 60 * 10
	}
	// validate callback URL
	if _, err := url.ParseRequestURI(callback); err != nil {
		http.Error(w, "invalid hub.callback URL", http.StatusBadRequest)
		return
	}

	//return 202, then spawn goroutine to asynchronously handle unsubs/subs
	w.WriteHeader(http.StatusAccepted)

	go func() {
		challenge := uuid.New().String()

		subKey := SubscriberKey{
			Callback: callback,
			Topic:    topic,
		}

		// if requesting unsubscribe, we check they're a subscriber before removing them from the map
		if mode == "unsubscribe" {
			log.Println("unsubscribing...")

			mutex.RLock()
			_, ok := subs[subKey]
			mutex.RUnlock()

			if !ok {
				notifyDenial(callback, topic, "not subscribed")
				return
			}

			if !verifyIntent(callback, mode, topic, challenge, leaseSeconds) {
				notifyDenial(callback, topic, "callback verification failed")
				return
			}

			mutex.Lock()
			delete(subs, subKey)
			mutex.Unlock()

			return
		}

		if !verifyIntent(callback, mode, topic, challenge, leaseSeconds) {
			notifyDenial(callback, topic, "callback verification failed")
			return
		}

		// add to map
		mutex.Lock()
		subs[subKey] = &Subscriber{
			Callback: callback,
			Topic:    topic,
			Secret:   secret,
			Expires:  time.Now().Add(time.Duration(leaseSeconds) * time.Second),
		}
		mutex.Unlock()
	}()

}

func notifyDenial(callback, topic, reason string) {
	v := url.Values{}
	v.Set("hub.mode", "denied")
	v.Set("hub.topic", topic)
	v.Set("hub.reason", reason)
	q := fmt.Sprintf("%s?%s", callback, v.Encode())

	_, _ = http.DefaultClient.Get(q)
}

func verifyIntent(callback, mode, topic, challenge string, lease int) bool {
	v := url.Values{}
	v.Set("hub.mode", mode)
	v.Set("hub.topic", topic)
	v.Set("hub.challenge", challenge)
	if mode == "subscribe" {
		v.Set("hub.lease_seconds", strconv.Itoa(lease))
	}
	q := fmt.Sprintf("%s?%s", callback, v.Encode())

	callbackURL, err := url.Parse(q)
	if err != nil {
		return false
	}

	resp, err := http.DefaultClient.Do(&http.Request{
		Method: http.MethodGet,
		URL:    callbackURL,
	})
	if err != nil {
		return false
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Callback verification failed with status: %d %s\n", resp.StatusCode, string(bodyBytes))
		return false
	}

	if string(bodyBytes) != challenge {
		return false
	}

	log.Println("verification complete", challenge)

	return true
}

func publishHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}
	topic := r.Form.Get("hub.topic")
	if topic == "" {
		http.Error(w, "hub.topic is required", http.StatusBadRequest)
		return
	}

	msg := &JSONResp{Data: "new data"}
	jsonBody, err := json.Marshal(msg)
	if err != nil {
		http.Error(w, "failed to marshal json", http.StatusInternalServerError)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for key, sub := range subs {
		if topic != key.Topic {
			continue
		}

		if time.Now().After(sub.Expires) {
			log.Printf("Subscriber %s for topic %s has expired", key.Callback, key.Topic)
			delete(subs, key)
			continue
		}

		sig := hmac.New(sha256.New, []byte(sub.Secret))
		sig.Write(jsonBody)
		sigHex := fmt.Sprintf("%x", sig.Sum(nil))

		req, _ := http.NewRequest("POST", key.Callback, bytes.NewReader(jsonBody))
		req.Header.Add("Content-Type", "application/json")
		if sub.Secret != "" {
			req.Header.Add("X-Hub-Signature", "sha256="+sigHex)
		}
		req.Header.Add("Link",
			fmt.Sprintf("<%s>; rel=\"self\", <%s>; rel=\"hub\"", key.Topic, "http://hub:8080"))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("Failed to post to %s: %v", key, err)
			continue
		}

		if resp.StatusCode >= http.StatusBadRequest {
			log.Printf("Failed to publish to %s: %d", key, resp.StatusCode)
			notifyDenial(key.Callback, key.Topic, "delivery failed, unsubscribed by hub")
			delete(subs, key)
		}

		resp.Body.Close()
		log.Printf("Published to %s with status %d", key, resp.StatusCode)
	}
}
