package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/keshav78-78/secure-cloud-box/internal/crypto"
	"github.com/keshav78-78/secure-cloud-box/internal/ui"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var server = env("SERVER_URL", "http://localhost:8080")
var bearer string

// ---------------- Path Helpers ----------------

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "\"")
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// makeObjectName: derive safe GCS object name from a local filename
func makeObjectName(localPath string) string {
	localPath = normalizePath(localPath)
	base := filepath.Base(localPath)
	s := base
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	return "user1/" + s + ".enc"
}

// ---------------- UI Styles ----------------

var (
	// Top title bar
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 4).
			Background(lipgloss.Color("#020617")). // very dark
			Foreground(lipgloss.Color("#E5E7EB")). // light gray
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#38BDF8")).
			MarginBottom(1)

	// "Server: ... • Bucket: ..." line
	headerMetaStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9CA3AF")).
			Italic(true)

	// Section headings: "Actions", "Upload File" etc.
	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#A6E3A1"))

	// Labels above inputs
	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			MarginBottom(0)

	// Generic help text at bottom
	helpStyle = lipgloss.NewStyle().
			Faint(true).
			Italic(true).
			Foreground(lipgloss.Color("#6B7280"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F97373")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4ADE80")).
			Bold(true)

	// Menu items
	menuItemStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("#E5E7EB"))

	menuItemSelectedStyle = lipgloss.NewStyle().
				Padding(0, 1).
				Foreground(lipgloss.Color("#0F172A")).
				Background(lipgloss.Color("#38BDF8")).
				Bold(true)

	// Progress box around forms / progress
	boxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#1F2937")).
			Padding(1, 2).
			MarginTop(1)

	// Progress bar container
	progressBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1).
			MarginTop(1)
)

// ---------------- Model ----------------

type phase int

const (
	phaseMenu phase = iota
	phaseUploadForm
	phaseDownloadForm
	phaseWorking
	phaseDone
	phaseError
)

type model struct {
	ph      phase
	menuIdx int

	pathIn textinput.Model
	objIn  textinput.Model

	sp     spinner.Model
	pg     progress.Model
	status string
	errMsg string

	total     int64
	completed int64
	doneMsg   string

	width int // terminal width for centering header
}

// ---------------- Init ----------------

func initialModel() model {
	ti1 := textinput.New()
	ti1.Placeholder = "Local file path (e.g., ./sample.txt)"
	ti1.Focus()
	ti1.Width = 60

	ti2 := textinput.New()
	ti2.Placeholder = "GCS object (e.g., user1/sample.txt.enc)"
	ti2.Width = 60

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	pg := progress.New(
		progress.WithScaledGradient("#22C55E", "#06B6D4"),
		progress.WithWidth(50),
	)

	return model{
		ph:      phaseMenu,
		menuIdx: 0,
		pathIn:  ti1,
		objIn:   ti2,
		sp:      sp,
		pg:      pg,
	}
}

type workDoneMsg struct {
	ok  bool
	msg string
	err error
}

// ---------------- Update ----------------

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// capture terminal width for centering header
	if wm, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = wm.Width
		return m, nil
	}

	switch m.ph {

	case phaseMenu:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "up", "k":
				if m.menuIdx > 0 {
					m.menuIdx--
				}
			case "down", "j":
				if m.menuIdx < 2 {
					m.menuIdx++
				}
			case "enter":
				switch m.menuIdx {
				case 0:
					m.ph = phaseUploadForm
					m.pathIn.SetValue("")
					m.objIn.SetValue("")
					m.pathIn.Focus()
				case 1:
					m.ph = phaseDownloadForm
					m.pathIn.SetValue("")
					m.objIn.SetValue("")
					m.objIn.Focus()
				case 2:
					return m, tea.Quit
				}
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			}
		}
		return m, nil

	case phaseUploadForm:
		var cmd tea.Cmd
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "tab":
				if m.pathIn.Focused() {
					m.pathIn.Blur()
					m.objIn.Focus()
				} else {
					m.objIn.Blur()
					m.pathIn.Focus()
				}
			case "ctrl+f":
				if m.pathIn.Focused() {
					// "*" => scan all drives / root with depth 5
					p, err := ui.PickFile("*", 5)
					if err != nil {
						m.errMsg = "picker: " + err.Error()
						return m, nil
					}
					if p != "" {
						p = normalizePath(p)
						m.pathIn.SetValue(p)
						if m.objIn.Value() == "" {
							m.objIn.SetValue(makeObjectName(p))
						}
					}
				}
			case "enter":
				if m.pathIn.Value() == "" || m.objIn.Value() == "" {
					m.errMsg = "file path & object name required"
					return m, nil
				}
				m.ph = phaseWorking
				m.status = "Encrypting and uploading..."
				return m, tea.Batch(m.sp.Tick, m.doUpload(m.pathIn.Value(), m.objIn.Value()))
			case "esc":
				m.ph = phaseMenu
			}
		}
		if m.pathIn.Focused() {
			m.pathIn, cmd = m.pathIn.Update(msg)
		} else {
			m.objIn, cmd = m.objIn.Update(msg)
		}
		return m, cmd

	case phaseDownloadForm:
		var cmd tea.Cmd
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "tab":
				if m.objIn.Focused() {
					m.objIn.Blur()
					m.pathIn.Focus()
				} else {
					m.pathIn.Blur()
					m.objIn.Focus()
				}
			case "enter":
				if m.objIn.Value() == "" {
					m.errMsg = "object name required"
					return m, nil
				}
				m.ph = phaseWorking
				m.status = "Downloading and decrypting..."
				return m, tea.Batch(m.sp.Tick, m.doDownload(m.objIn.Value(), m.pathIn.Value()))
			case "esc":
				m.ph = phaseMenu
			}
		}
		if m.objIn.Focused() {
			m.objIn, cmd = m.objIn.Update(msg)
		} else {
			m.pathIn, cmd = m.pathIn.Update(msg)
		}
		return m, cmd

	case phaseWorking:
		switch msg := msg.(type) {
		case spinner.TickMsg:
			var cmd tea.Cmd
			m.sp, cmd = m.sp.Update(msg)
			return m, cmd
		case workDoneMsg:
			if msg.ok {
				m.ph = phaseDone
				m.doneMsg = msg.msg
			} else {
				m.ph = phaseError
				m.errMsg = msg.err.Error()
			}
			return m, nil
		case tea.KeyMsg:
			if msg.String() == "esc" {
				m.ph = phaseMenu
				return m, nil
			}
		}
		return m, nil

	case phaseDone:
		if _, ok := msg.(tea.KeyMsg); ok {
			m.ph = phaseMenu
		}
		return m, nil

	case phaseError:
		if _, ok := msg.(tea.KeyMsg); ok {
			m.ph = phaseMenu
		}
		return m, nil
	}

	return m, nil
}

// ---------------- View ----------------

func (m model) View() string {
	// Title text
	title := titleStyle.Render(" SecureBox CLI ")

	// Center header horizontally if terminal width known
	var header string
	if m.width > 0 {
		header = lipgloss.PlaceHorizontal(m.width, lipgloss.Center, title)
	} else {
		header = title
	}

	serverInfo := fmt.Sprintf("%s", server)
	bucket := env("GCS_BUCKET", "unset")
	metaLine := headerMetaStyle.Render(
		fmt.Sprintf("Server: %s  •  Bucket: %s", serverInfo, bucket),
	)

	var body string
	var footer string

	switch m.ph {

	case phaseMenu:
		menu := boxStyle.Render(
			sectionStyle.Render("Actions") + "\n\n" +
				menuLine(0, m.menuIdx == 0, "Upload file (Encrypt → KMS → GCS)") + "\n" +
				menuLine(1, m.menuIdx == 1, "Download file (GCS → KMS → Decrypt)") + "\n" +
				menuLine(2, m.menuIdx == 2, "Quit SecureBox"),
		)
		footer = helpStyle.Render("↑/↓ navigate  •  Enter select  •  q quit")
		body = menu

	case phaseUploadForm:
		form := sectionStyle.Render("Upload file") + "\n\n" +
			labelStyle.Render("Local file path:") + "\n" + m.pathIn.View() + "\n\n" +
			labelStyle.Render("GCS object name:") + "\n" + m.objIn.View()

		if m.errMsg != "" {
			form += "\n\n" + errorStyle.Render(m.errMsg)
		}

		body = boxStyle.Render(form)
		footer = helpStyle.Render("Tab switch  •  Enter start  •  Esc back  •  Ctrl+F file picker")

	case phaseDownloadForm:
		form := sectionStyle.Render("Download file") + "\n\n" +
			labelStyle.Render("GCS object name (stored in bucket):") + "\n" + m.objIn.View() + "\n\n" +
			labelStyle.Render("Output path (optional, default = original name):") + "\n" + m.pathIn.View()

		if m.errMsg != "" {
			form += "\n\n" + errorStyle.Render(m.errMsg)
		}

		body = boxStyle.Render(form)
		footer = helpStyle.Render("Tab switch  •  Enter start  •  Esc back")

	case phaseWorking:
		ratio := 0.0
		if m.total > 0 {
			ratio = float64(m.completed) / float64(m.total)
		}
		bar := m.pg.ViewAs(ratio)

		content := sectionStyle.Render("Processing") + "\n\n" +
			lipgloss.NewStyle().Bold(true).Render(m.status) + "\n\n" +
			progressBox.Render(bar)

		body = boxStyle.Render(content)
		footer = helpStyle.Render("Esc cancel/back")

	case phaseDone:
		content := successStyle.Render("Done: " + m.doneMsg)
		body = boxStyle.Render(content)
		footer = helpStyle.Render("Press any key to return to menu")

	case phaseError:
		content := errorStyle.Render("Error: " + m.errMsg)
		body = boxStyle.Render(content)
		footer = helpStyle.Render("Press any key to return to menu")

	default:
		body = "..."
	}

	return fmt.Sprintf("%s\n%s\n\n%s\n\n%s", header, metaLine, body, footer)
}

func menuLine(_ int, selected bool, text string) string {
	// optional: agar number bhi dikhana hai to use:
	// label := fmt.Sprintf("%d.", i+1)

	if selected {
		// selected: arrow + highlight + bold (selected style)
		line := fmt.Sprintf("> %s", text)
		return menuItemSelectedStyle.Render(line)
	}

	// normal: sirf indent, no arrow
	line := fmt.Sprintf("  %s", text)
	return menuItemStyle.Render(line)
}

// ---------------- Work Commands ----------------

func (m model) doUpload(path, object string) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		plain, err := os.ReadFile(path)
		if err != nil {
			return workDoneMsg{err: err}
		}

		dek, err := crypto.GenerateDEK()
		if err != nil {
			return workDoneMsg{err: err}
		}
		nonce, ct, err := crypto.EncryptAESGCM(plain, dek, []byte(object))
		if err != nil {
			return workDoneMsg{err: err}
		}

		wrapResp := struct {
			Wrapped string `json:"wrapped_b64"`
		}{}
		if err := postJSON("/v1/wrap-dek", map[string]string{
			"dek_b64": base64.StdEncoding.EncodeToString(dek),
		}, &wrapResp); err != nil {
			return workDoneMsg{err: fmt.Errorf("wrap dek: %w", err)}
		}

		sign := struct {
			URL string `json:"url"`
		}{}
		if err := getJSON("/v1/sign-upload?name="+object, &sign); err != nil {
			return workDoneMsg{err: err}
		}

		req, _ := http.NewRequestWithContext(ctx, "PUT", sign.URL, bytes.NewReader(ct))
		req.Header.Set("Content-Type", "application/octet-stream")
		client := &http.Client{Timeout: 0}
		res, err := client.Do(req)
		if err != nil {
			return workDoneMsg{err: err}
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			b, _ := io.ReadAll(res.Body)
			return workDoneMsg{err: fmt.Errorf("upload failed: %s %s", res.Status, string(b))}
		}

		err = postNoResp("/v1/save-meta", map[string]any{
			"object_name":  object,
			"wrapped_b64":  wrapResp.Wrapped,
			"nonce_b64":    base64.StdEncoding.EncodeToString(nonce),
			"orig_name":    filepath.Base(path),
			"content_type": "application/octet-stream",
			"size":         len(ct),
		})
		if err != nil {
			return workDoneMsg{err: err}
		}
		return workDoneMsg{ok: true, msg: fmt.Sprintf("Uploaded %s", object)}
	}
}

func (m model) doDownload(object, outPath string) tea.Cmd {
	return func() tea.Msg {
		meta := struct {
			Wrapped string `json:"wrapped_b64"`
			Nonce   string `json:"nonce_b64"`
			Orig    string `json:"orig_name"`
		}{}
		if err := getJSON("/v1/get-meta?name="+object, &meta); err != nil {
			return workDoneMsg{err: err}
		}

		// Default download folder
		defaultDir := "D:/go-projects/Secure-Cloud-Box/decrypt-files"

		if strings.TrimSpace(outPath) == "" {
			outPath = filepath.Join(defaultDir, meta.Orig)
		} else {
			outPath = strings.TrimSpace(outPath)
			outPath = strings.Trim(outPath, "\"")
			outPath = strings.ReplaceAll(outPath, "\\", "/")

			if strings.HasSuffix(outPath, "/") || strings.HasSuffix(outPath, "\\") {
				outPath = filepath.Join(outPath, meta.Orig)
			}
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return workDoneMsg{err: fmt.Errorf("create dir: %w", err)}
		}

		sign := struct {
			URL string `json:"url"`
		}{}
		if err := getJSON("/v1/sign-download?name="+object, &sign); err != nil {
			return workDoneMsg{err: err}
		}
		res, err := http.Get(sign.URL)
		if err != nil {
			return workDoneMsg{err: err}
		}
		defer res.Body.Close()
		ct, _ := io.ReadAll(res.Body)

		uw := struct {
			DEK string `json:"dek_b64"`
		}{}
		if err := postJSON("/v1/unwrap-dek", map[string]string{"wrapped_b64": meta.Wrapped}, &uw); err != nil {
			return workDoneMsg{err: err}
		}
		dek, _ := base64.StdEncoding.DecodeString(uw.DEK)
		nonce, _ := base64.StdEncoding.DecodeString(meta.Nonce)
		pt, err := crypto.DecryptAESGCM(nonce, ct, dek, []byte(object))
		if err != nil {
			return workDoneMsg{err: err}
		}

		if err := os.WriteFile(outPath, pt, 0644); err != nil {
			return workDoneMsg{err: err}
		}
		return workDoneMsg{ok: true, msg: "Downloaded → " + outPath}
	}
}

// ---------------- Auth & Request Helpers ----------------

func loginOnce() error {
	if bearer != "" {
		return nil
	}
	body := map[string]string{
		"user": env("AUTH_USER", env("DEMO_USER", "keshav")),
		"pass": env("AUTH_PASS", env("DEMO_PASS", "pass123")),
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := postJSONNoAuth("/v1/login", body, &out); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	bearer = out.Token
	return nil
}

func authedReq(req *http.Request) {
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
}

func postJSON(path string, body any, out any) error {
	if err := loginOnce(); err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", server+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	authedReq(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, string(x))
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func postNoResp(path string, body any) error {
	if err := loginOnce(); err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", server+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	authedReq(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, string(x))
	}
	return nil
}

func getJSON(path string, out any) error {
	if err := loginOnce(); err != nil {
		return err
	}
	req, _ := http.NewRequest("GET", server+path, nil)
	authedReq(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, string(x))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func postJSONNoAuth(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	res, err := http.Post(server+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		x, _ := io.ReadAll(res.Body)
		return fmt.Errorf("status %s: %s", res.Status, string(x))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// ---------------- Misc & main ----------------

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func init() {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	var srv string
	if len(os.Args) > 1 {
		fs.StringVar(&srv, "server", "", "server base URL (default from SERVER_URL)")
		fs.Parse(os.Args[1:])
		if srv != "" {
			server = srv
		}
	}
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
