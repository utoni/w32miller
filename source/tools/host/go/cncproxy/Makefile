GOCC ?= go
RM ?= rm
GOPATH := $(shell realpath ./deps)
INSTALL ?= install
DESTDIR ?= .
BIN := cncproxy
ifeq ($(strip $(GOARCH)),)
BIN := $(BIN)-host
else
BIN := $(BIN)-$(GOARCH)$(GOARM)
endif
SRCS := main.go manager.go http.go
DEP_CNCLIB := ../cnclib/miller_consts.go ../cnclib/miller_victim.go
DEP_MUX := deps/src/github.com/gorilla/mux/mux.go
DEP_PACKER := deps/src/github.com/zhuangsirui/binpacker/packer.go

all: $(BIN)

%.go:

$(DEP_MUX):
	GOPATH=$(GOPATH) $(GOCC) get -v -u github.com/gorilla/mux

$(DEP_PACKER):
	GOPATH=$(GOPATH) $(GOCC) get -v github.com/zhuangsirui/binpacker

$(BIN): $(DEP_MUX) $(DEP_PACKER) $(DEP_CNCLIB) $(SRCS)
ifeq ($(strip $(IS_GCCGO)),)
	GOPATH=$(GOPATH) $(GOCC) build -ldflags="-s -w" -o $(BIN) .
else
	GOPATH=$(GOPATH) $(GOCC) build -gccgoflags="-s -w -pthread" -o $(BIN) .
endif

$(BIN)-install: $(BIN)
	$(INSTALL) -D $(BIN) $(DESTDIR)/$(BIN)

install: $(BIN)-install

clean:
	$(RM) -f $(BIN) $(DESTDIR)/$(BIN)

.PHONY: all
