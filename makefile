ENV_FILE := $(CURDIR)/.env
ifneq ("$(wildcard $(ENV_FILE))","")
    include $(ENV_FILE)
    export $(shell sed 's/=.*//' $(ENV_FILE))
endif

PROJECT      ?= securebox-8595
GCS_BUCKET   ?= securebox-keshav-demo-001
PORT         ?= 8080
SERVER_URL   ?= http://localhost:8080
DB_PATH      ?= securebox.db

.PHONY: help setup server tui client clean env dev dev-win dev-bg stop

help:
	@echo ""
	@echo " SecureBox CLI"
	@echo "------------------------------------------"
	@echo "make setup      - Install dependencies"
	@echo "make server     - Start backend server"
	@echo "make tui        - Start TUI client"
	@echo "make dev        - Start server + tui (Unix-like)"
	@echo "make dev-win    - Start server + tui (Windows)"
	@echo "make dev-bg     - Start server + tui in background (Unix-like)"
	@echo "make clean      - Remove binaries and DB"
	@echo "make env        - Show environment variables"
	@echo ""

setup:
	go mod tidy

server:
	go run ./cmd/securebox-server

tui:
	go run ./cmd/securebox-tui

client:
	mkdir -p bin
	go build -o bin/securebox-server ./cmd/securebox-server
	go build -o bin/securebox-tui ./cmd/securebox-tui

clean:
	rm -rf bin
	rm -f $(DB_PATH)

env:
	@echo ""
	@echo "PROJECT:          $(PROJECT)"
	@echo "GCS_BUCKET:       $(GCS_BUCKET)"
	@echo "KMS_KEY_NAME:     $(KMS_KEY_NAME)"
	@echo "GOOGLE_CREDS:     $(GOOGLE_APPLICATION_CREDENTIALS)"
	@echo "SERVER_URL:       $(SERVER_URL)"
	@echo "PORT:             $(PORT)"
	@echo ""

# For Linux / WSL / Git Bash etc.
dev:
	@echo "Starting server (background) + TUI (foreground)..."
	@nohup sh -c 'go run ./cmd/securebox-server > server.log 2>&1 &' ; \
	sleep 1 ; \
	go run ./cmd/securebox-tui

dev-bg:
	@echo "Starting server + TUI in background..."
	@nohup sh -c 'go run ./cmd/securebox-server > server.log 2>&1 &' ; \
	sleep 1 ; \
	nohup sh -c 'go run ./cmd/securebox-tui > tui.log 2>&1 &' ; \
	echo "Started (logs: server.log, tui.log)"


dev-win:
	@echo "Starting server + TUI in separate Windows terminals..."
	@cmd.exe /C start "SecureBox Server" cmd /K "cd /d $(CURDIR) && go run .\cmd\securebox-server"
	@timeout /t 2 /nobreak >nul
	@cmd.exe /C start "SecureBox TUI" cmd /K "cd /d $(CURDIR) && go run .\cmd\securebox-tui"
	@echo "Both windows started."

stop:
	-@pkill -f cmd/securebox-server 2>/dev/null || true
	-@pkill -f cmd/securebox-tui 2>/dev/null || true
	@echo "Stopped (if running)."
