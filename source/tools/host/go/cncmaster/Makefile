GOCC ?= go
RM ?= rm
GOPATH := $(shell realpath ./deps)
INSTALL ?= install
DESTDIR ?= .
BIN := cncmaster
ifeq ($(strip $(GOARCH)),)
BIN := $(BIN)-host
else
BIN := $(BIN)-$(GOARCH)$(GOARM)
endif
SRCS := main.go http.go
DEP_MUX := deps/src/github.com/gorilla/mux/mux.go

all: $(BIN)

%.go:

$(DEP_MUX):
	GOPATH=$(GOPATH) $(GOCC) get -v -u github.com/gorilla/mux

$(BIN): $(DEP_MUX) $(SRCS)
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
