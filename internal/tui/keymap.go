package tui

// Key bindings
type keyMap struct {
	Up     string
	Down   string
	Start  string
	Pause  string
	Stop   string
	Exec   string
	Search string
	Help   string
	Quit   string
	Tab    string
}

var keys = keyMap{
	Up:     "up",
	Down:   "down",
	Start:  "s",
	Pause:  "p",
	Stop:   "x",
	Exec:   "e",
	Search: "/",
	Help:   "?",
	Quit:   "q",
	Tab:    "tab",
}
