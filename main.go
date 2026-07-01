package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/versus/wg-webui/db"
	"github.com/versus/wg-webui/web"
	"github.com/versus/wg-webui/wgconf"
	"github.com/versus/wg-webui/wireguard"
)

// logFile is an io.Writer that can reopen the underlying file on demand,
// which is needed for logrotate to truncate/replace the file while the
// process keeps running.
type logFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openLogFile(path string) (*logFile, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &logFile{path: path, f: f}, nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Write(p)
}

func (l *logFile) Reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.f.Close()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

func main() {
	wgIface := flag.String("wg-interface", "wg0", "WireGuard interface name")
	wgConfig := flag.String("wg-config", "/etc/wireguard/wg0.conf", "path to WireGuard config file")
	listenPort := flag.String("listen", "5000", "web UI port (always bound to 127.0.0.1)")
	dbPath := flag.String("db", "", "path to SQLite database (default: same dir as --wg-config, named <interface>.db)")
	logPath := flag.String("log", "", "path to log file (default: stdout)")
	resetPassword := flag.Bool("reset-password", false, "reset web UI password interactively and exit")
	flag.Parse()

	// derive default db path
	resolvedDB := *dbPath
	if resolvedDB == "" {
		resolvedDB = filepath.Join(
			filepath.Dir(*wgConfig),
			strings.TrimSuffix(filepath.Base(*wgConfig), ".conf")+".db",
		)
	}

	// --reset-password: minimal mode — open DB, prompt, save hash, exit
	if *resetPassword {
		database, err := db.Open(resolvedDB)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		defer database.Close()

		fmt.Print("Новый пароль: ")
		pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("read password: %v", err)
		}
		fmt.Print("Подтверждение: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("read password: %v", err)
		}
		if string(pw1) != string(pw2) {
			fmt.Fprintln(os.Stderr, "Ошибка: пароли не совпадают.")
			os.Exit(1)
		}
		if len(pw1) == 0 {
			fmt.Fprintln(os.Stderr, "Ошибка: пароль не может быть пустым.")
			os.Exit(1)
		}
		hash, err := bcrypt.GenerateFromPassword(pw1, 12)
		if err != nil {
			log.Fatalf("hash password: %v", err)
		}
		if err := database.SetPasswordHash(string(hash)); err != nil {
			log.Fatalf("save password: %v", err)
		}
		fmt.Println("Пароль успешно обновлён.")
		return
	}

	// normal startup
	var logWriter io.Writer = os.Stdout
	var lf *logFile
	if *logPath != "" {
		var err error
		lf, err = openLogFile(*logPath)
		if err != nil {
			log.Fatalf("open log file: %v", err)
		}
		logWriter = lf
	}
	logger := slog.New(slog.NewTextHandler(logWriter, nil))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				if lf != nil {
					if err := lf.Reopen(); err != nil {
						logger.Error("failed to reopen log file", "err", err)
					} else {
						logger.Info("log file reopened")
					}
				}
			case syscall.SIGTERM, syscall.SIGINT:
				logger.Info("service stopping", "signal", sig.String())
				os.Exit(0)
			}
		}
	}()

	// parse wg config for subnet, port, private key path
	wgCfg, err := wgconf.ParseFile(*wgConfig)
	if err != nil {
		logger.Error("parse wg config", "err", err)
		os.Exit(1)
	}

	// open database
	database, err := db.Open(resolvedDB)
	if err != nil {
		logger.Error("open db", "err", err, "path", resolvedDB)
		os.Exit(1)
	}
	defer database.Close()

	sessionKey, err := database.EnsureSessionKey()
	if err != nil {
		logger.Error("ensure session key", "err", err)
		os.Exit(1)
	}

	host, _, _ := database.GetSetting("host")
	dns, _, _ := database.GetSetting("dns")

	store := db.NewStore(database)

	svc := wireguard.NewService(wireguard.ServiceConfig{
		Interface:  *wgIface,
		ConfigFile: *wgConfig,
		Subnet:     wgCfg.Subnet,
		ServerHost: host,
		ServerPort: wgCfg.ListenPort,
		DNS:        dns,
	}, store)

	listenAddr := "127.0.0.1:" + *listenPort

	h, err := web.NewHandler(store, database, svc, sessionKey, listenAddr, *wgIface, logger)
	if err != nil {
		log.Fatalf("init handler: %v", err)
	}

	mux := web.NewServeMux(h)

	logger.Info("service starting", "addr", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
