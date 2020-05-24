package miller

import (
    "fmt"
)


const KEY_256 uint8 = (256/8)
const MARKER_SIZ uint8 = 8
const AESKEY_SIZ uint8 = 32
const HW_PROFILE_GUIDLEN uint8 = 39
const MAX_PROFILE_LEN uint8 = 80

const RF_INITIAL uint8 = 0x00
const RF_AGAIN   uint8 = 0x41
const RF_ERROR   uint8 = 0x42
const RF_OK      uint8 = 0x66

const RC_INFO     uint16 = 0xACAB
const RC_REGISTER uint16 = 0xAABB
const RC_PING     uint16 = 0x0043
const RC_SHELL    uint16 = 0x0044

func RCtoString(rc uint16) string {
    switch rc {
        case RC_INFO:
            return "RC_INFO"
        case RC_REGISTER:
            return "RC_REGISTER"
        case RC_PING:
            return "RC_PING"
        case RC_SHELL:
            return "RC_SHELL"
        default:
            return "UNKNOWN"
    }
}

type HttpResp struct {
    StartMarker [MARKER_SIZ]byte
    RespFlags   uint8
    RespCode    uint16
    Pkgsiz      uint32
    Pkgbuf      []byte
}

func (hr *HttpResp) String() string {
    return fmt.Sprintf("Marker: '%s', Flags: 0x%04X, Code: 0x%04X, " +
                       "PKGSIZ: 0x%04X, PKGBUF: '%v'",
        hr.StartMarker, hr.RespFlags, hr.RespCode,
        hr.Pkgsiz, hr.Pkgbuf)
}

type RespRegister struct {
    Aeskey     [AESKEY_SIZ]byte
    NextPing   uint32
}

type RespPong struct {
    NextPing   uint32
}

type RespShell struct {
    Operation   uint8
    Showcmd     uint8
    FileLen     uint16
    ParamLen    uint16
    DirLen      uint16
    Data        []byte
}

type SYSTEM_INFO_32 struct {
    ProcessorArchitecture     uint16
    Reserved                  uint16
    PageSize                  uint32
    MinimumApplicationAddress uint32
    MaximumApplicationAddress uint32
    ActiveProcessorMask       uint32
    NumberOfProcessors        uint32
    ProcessorType             uint32
    AllocationGranularity     uint32
    ProcessorLevel            uint16
    ProcessorRevision         uint16
}

type HW_PROFILE_INFOA struct {
    DockInfo      uint32
    HwProfileGuid [HW_PROFILE_GUIDLEN]byte
    HwProfileName [MAX_PROFILE_LEN]byte
}

type ReqInfo struct {
    SI          SYSTEM_INFO_32
    HW          HW_PROFILE_INFOA
    CmdLineLen  uint16
    DevsLen     uint8
    Data        []byte
}
