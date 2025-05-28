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

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const defaultPort = "8080"

var (
	// callback -> topic
	subs = make(map[string]*Subscriber)
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", postHandler).Methods("POST")
	r.HandleFunc("/publish", publishHandler).Methods("POST")

	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"*"})
	methodsOk := handlers.AllowedMethods([]string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodOptions,
	})

	fmt.Printf("Starting server on port %s...\n", defaultPort)
	log.Fatal(http.ListenAndServe(":"+defaultPort, handlers.CORS(originsOk, headersOk, methodsOk)(r)))

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

	/*
			Key: hub.callback, Value: [http://web-sub-client:8080/ypnEOVClLR]
		  Key: hub.mode, Value: [subscribe]
		  Key: hub.secret, Value: [SgDhyNlTpRliPFRlHEdr]
		  Key: hub.topic, Value: [a-topic]
	*/

	if params.Get("hub.mode") == "unsubscribe" {
		fmt.Println("unsubscribing...")
		cb, ok := subs[params.Get("hub.callback")]
		if !ok {
			http.Error(w, "cannot unsubscribe without being a subscriber", http.StatusBadRequest)
			return
		}

		delete(subs, cb.Callback)

		return
	} else if params.Get("hub.mode") != "subscribe" {
		http.Error(w, "unsupported hub mode", http.StatusBadRequest)
		return
	}

	hubBody := &JSONResp{Data: "hello"}
	jsonBody, err := json.Marshal(hubBody)
	if err != nil {
		http.Error(w, "failed to marshal body", http.StatusInternalServerError)
		return
	}

	secret := uuid.New().String()

	q := fmt.Sprintf("%s?hub.mode=%s&hub.topic=%s&hub.challenge=%s", params.Get("hub.callback"), params.Get("hub.mode"), params.Get("hub.topic"), secret)

	callbackURL, err := url.Parse(q)
	if err != nil {
		http.Error(w, "invalid callback URL", http.StatusBadRequest)
		return
	}

	h := http.Header{}
	h.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(&http.Request{
		Method: http.MethodGet,
		URL:    callbackURL,
		Header: h,
	})
	if err != nil {
		http.Error(w, "failed to call callback url", http.StatusBadRequest)
		return
	}

	sig := hmac.New(sha256.New, []byte(params.Get("hub.secret")))
	sig.Write(jsonBody)
	sigHex := fmt.Sprintf("%x", sig.Sum(nil))

	h.Add("X-Hub-Signature", "sha256="+sigHex)

	bodyBytes, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Callback verification failed with status: %d %s\n", resp.StatusCode, string(bodyBytes))
		http.Error(w, "callback verification failed", http.StatusBadRequest)
		return
	}

	fmt.Printf("Response from callback: %d %s\n", resp.StatusCode, string(bodyBytes))

	if string(bodyBytes) != secret {
		http.Error(w, "secret did not match", http.StatusUnauthorized)
		return
	}

	fmt.Println("CALLBACK URL", params.Get("hub.callback"))

	subs[params.Get("hub.callback")] = &Subscriber{
		Callback: params.Get("hub.callback"),
		Topic:    params.Get("hub.topic"),
		Secret:   params.Get("hub.secret"),
	}

	fmt.Println("current subscribers", subs)

	callbackURL, err = url.Parse(params.Get("hub.callback"))
	if err != nil {
		http.Error(w, "invalid callback URL", http.StatusBadRequest)
		return
	}

	resp, err = http.DefaultClient.Do(&http.Request{
		Method: http.MethodPost,
		URL:    callbackURL,
		Header: h,
		Body:   io.NopCloser(bytes.NewReader(jsonBody)),
	})

	if err != nil {
		http.Error(w, "failed to call callback url", http.StatusBadRequest)
		return
	}
	fmt.Println("sha256=" + sigHex)
	fmt.Println("post", resp.StatusCode)

}

func publishHandler(w http.ResponseWriter, r *http.Request) {
	msg := &JSONResp{Data: "new data"}
	jsonBody, _ := json.Marshal(msg)

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
