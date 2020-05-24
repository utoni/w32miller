package main

import (
    "../cnclib"

    "sync"
)

type victim_data struct {
    v       *miller.Victim
    in_use  bool
    lock    sync.Mutex
}

type manager struct {
    victims map[string]victim_data
    lock sync.Mutex
}


func NewManager() manager {
    return manager{ make(map[string]victim_data), sync.Mutex{} }
}

func (m *manager) SetVictim(v *miller.Victim, sid *string) {
    m.lock.Lock()
    defer m.lock.Unlock()
    vd := victim_data{}
    vd.v = v
    m.victims[*sid] = vd
}

func (m *manager) getVictim(sid *string) *victim_data {
    m.lock.Lock()
    defer m.lock.Unlock()
    ret, ok := m.victims[*sid]
    if ok {
        return &ret
    }
    return nil
}

func (m *manager) GetVictim(sid *string) *miller.Victim {
    vd := m.getVictim(sid)
    if vd == nil {
        return nil
    }
    if !m.VictimInUse(sid) {
        return vd.v
    }
    return nil
}

func (m *manager) VictimInUse(sid *string) bool {
    vd := m.getVictim(sid)
    if vd == nil {
        return false
    }
    vd.lock.Lock()
    defer vd.lock.Unlock()
    return vd.in_use
}

func (m *manager) PushVictim(sid *string) bool {
    if m.VictimInUse(sid) {
        return false
    }
    vd := m.getVictim(sid)
    vd.lock.Lock()
    defer vd.lock.Unlock()
    vd.in_use = true
    return true
}

func (m *manager) PopVictim(sid *string) bool {
    if !m.VictimInUse(sid) {
        return false
    }
    vd := m.getVictim(sid)
    vd.lock.Lock()
    defer vd.lock.Unlock()
    vd.in_use = false
    return true
}
