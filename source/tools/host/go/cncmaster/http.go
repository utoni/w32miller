package main

import (
    "github.com/gorilla/mux"

    "log"
    "net/http"
)


func miller_http_handler(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    sid, ok := params["sid"]
    if !ok {
        return
    }
    marker, ok := params["marker"]
    if !ok {
        return
    }
    rnd, ok := params["rnd"]
    if !ok {
        return
    }

    log.Printf("SID '%s' with MARKER '%s' and RND '%s'", sid, marker, rnd)

    w.Write([]byte("Hello!"))
}
