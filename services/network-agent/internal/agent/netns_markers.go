package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Lab namespaces live in /run/netns, so their ownership markers live in /run as well: both vanish
// on reboot. A marker records which process created a namespace, so a later run can tell a
// namespace left behind by a crashed session (owner gone) from one that is still in use.
const defaultLabMarkerDir = "/run/egresslab/netns"

const labMarkerVersion = 1

type labMarker struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	PID       int       `json:"pid"`
	PIDStart  string    `json:"pid_start"`
	CreatedAt time.Time `json:"created_at"`
}

type labMarkers struct {
	dir   string
	pid   int
	start string
	now   func() time.Time
}

func newLabMarkers(dir string) (*labMarkers, error) {
	pid := os.Getpid()

	start, err := processStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("read own process start time: %w", err)
	}

	return &labMarkers{dir: dir, pid: pid, start: start, now: time.Now}, nil
}

func (m *labMarkers) path(name string) string {
	return filepath.Join(m.dir, name+".json")
}

func (m *labMarkers) write(name string) error {
	data, err := json.Marshal(labMarker{
		Version:   labMarkerVersion,
		Name:      name,
		PID:       m.pid,
		PIDStart:  m.start,
		CreatedAt: m.now().UTC(),
	})
	if err != nil {
		return err
	}

	if err := writePrivateFile(m.path(name), append(data, '\n')); err != nil {
		return fmt.Errorf("write ownership marker for %s: %w", name, err)
	}

	return nil
}

func (m *labMarkers) remove(name string) error {
	err := os.Remove(m.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}

// read returns the marker for name; ok is false when there is none.
func (m *labMarkers) read(name string) (labMarker, bool, error) {
	data, err := readPrivateFile(m.path(name), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return labMarker{}, false, nil
	}

	if err != nil {
		return labMarker{}, false, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var marker labMarker
	if err := decoder.Decode(&marker); err != nil {
		return labMarker{}, false, fmt.Errorf("parse marker for %s: %w", name, err)
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return labMarker{}, false, fmt.Errorf("parse marker for %s: trailing data", name)
	}

	if marker.Version != labMarkerVersion || marker.Name != name || marker.PID <= 0 || marker.PIDStart == "" {
		return labMarker{}, false, fmt.Errorf("marker for %s is malformed", name)
	}

	return marker, true, nil
}

// names lists the namespaces that have markers.
func (m *labMarkers) names() ([]string, error) {
	entries, err := os.ReadDir(m.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		name, ok := strings.CutSuffix(entry.Name(), ".json")
		if ok && entry.Type().IsRegular() && labNamePattern.MatchString(name) {
			names = append(names, name)
		}
	}

	return names, nil
}

// processStartTime returns field 22 of /proc/<pid>/stat (start time in clock ticks since boot),
// which together with the PID identifies a process even after PID reuse.
func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}

	return parseProcStatStart(string(data))
}

func parseProcStatStart(stat string) (string, error) {
	// The command name (field 2) is in parentheses and may contain spaces or ')'.
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", errors.New("malformed /proc stat")
	}

	fields := strings.Fields(stat[end+1:])

	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return "", errors.New("malformed /proc stat")
	}

	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("malformed /proc stat start time")
	}

	return fields[19], nil
}

func processAlive(pid int, start string) bool {
	current, err := processStartTime(pid)
	return err == nil && current == start
}
