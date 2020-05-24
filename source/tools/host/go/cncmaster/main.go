package main

import (
    "github.com/gorilla/mux"

    "log"
    "net/http"
)


const verbose = true
const listen_tpl = "127.0.0.1:8081"

func main() {
    rtr := mux.NewRouter()
    rtr.HandleFunc("/.miller_{sid:[a-zA-Z0-9]{32}}_{marker:[a-zA-Z0-9]{8}}_{rnd:[a-zA-Z0-9]{64}}", miller_http_handler).Methods("POST")

    http.Handle("/", rtr)

    log.Println("CNCMASTER: Listening on " + listen_tpl + "...")
    http.ListenAndServe(listen_tpl, logRequest(http.DefaultServeMux))
}

func logRequest(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if verbose {
            log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
        }
        handler.ServeHTTP(w, r)
    })
}
