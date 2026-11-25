package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const (
	reservationAuthorityFile         = "reservation-authority.json"
	reservationAuthorityJournalMagic = "egresslab-reservations/v2\n"
	maxReservationAuthorityBytes     = 8192
)

var (
	ErrReservationAuthorityExists   = errors.New("reservation authority already provisioned")
	ErrReservationAuthorityMismatch = errors.New("reservation authority identity mismatch")

	reservationAuthorityIDPattern = regexp.MustCompile(`^authority_[0-9a-f]{32}$`)
)

// ReservationAuthorityInfo is the immutable initialization marker: the authority's identity, its
// canonical directory and the controller key it is bound to.
type ReservationAuthorityInfo struct {
	Version         int    `json:"version"`
	ID              string `json:"id"`
	Directory       string `json:"directory"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

func (i ReservationAuthorityInfo) valid() bool {
	return i.Version == 1 &&
		reservationAuthorityIDPattern.MatchString(i.ID) &&
		filepath.IsAbs(i.Directory) &&
		filepath.Clean(i.Directory) == i.Directory &&
		labFingerprintPattern.MatchString(i.PublicKeySHA256)
}

// ReservationAuthority is an opened authority bound to one directory and one controller key. It is
// not an activation grant.
type ReservationAuthority struct {
	info ReservationAuthorityInfo
}

func (a *ReservationAuthority) Info() ReservationAuthorityInfo {
	if a == nil {
		return ReservationAuthorityInfo{}
	}

	return a.info
}

func newReservationAuthorityID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}

	return "authority_" + hex.EncodeToString(raw[:]), nil
}

// canonicalAuthorityDirectory resolves aliases of one directory to one path. A moved directory no
// longer matches its marker. It does not defend against an administrator changing the filesystem.
func canonicalAuthorityDirectory(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", ErrReservationUnavailable
	}

	dir, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return "", errors.Join(ErrReservationUnavailable, err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return "", errors.Join(ErrReservationUnavailable, err)
	}

	if !info.IsDir() {
		return "", ErrReservationUnavailable
	}

	return filepath.Clean(dir), nil
}

// reservationAuthorityFingerprint needs the public key only; the private key stays in the key store.
func reservationAuthorityFingerprint(signer LabSigner) (string, error) {
	if signer == nil {
		return "", ErrReservationUnavailable
	}

	public, err := signer.PublicKey()
	if err != nil {
		return "", err
	}

	if len(public) != ed25519.PublicKeySize {
		return "", ErrReservationAuthorityMismatch
	}

	return LabPublicKeySHA256(public), nil
}

// authorityJournalHeader binds a V2 journal to its marker. The digest detects a journal from another
// authority; it is not an attestation against someone who can write both files.
func authorityJournalHeader(info ReservationAuthorityInfo) (string, error) {
	if !info.valid() {
		return "", ErrReservationAuthorityMismatch
	}

	payload, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(payload)

	return reservationAuthorityJournalMagic + hex.EncodeToString(digest[:]) + "\n", nil
}

// InitializeReservationAuthority provisions a new authority once: the marker is published first,
// then the bound journal, each complete or not at all. It never repairs or replaces an existing
// marker or journal; after an interrupted run the leftover marker blocks initialization until a
// trusted recovery exists.
func InitializeReservationAuthority(root string, signer LabSigner) (ReservationAuthorityInfo, error) {
	if root == "" || !filepath.IsAbs(root) {
		return ReservationAuthorityInfo{}, ErrReservationUnavailable
	}

	fingerprint, err := reservationAuthorityFingerprint(signer)
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	// Only explicit provisioning creates the directory.
	if err := os.MkdirAll(root, 0o700); err != nil {
		return ReservationAuthorityInfo{}, errors.Join(ErrReservationUnavailable, err)
	}

	dir, err := canonicalAuthorityDirectory(root)
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	// Neither may exist, not even as a broken symlink or a leftover of an interrupted run.
	for _, name := range []string{reservationAuthorityFile, reservationJournalFile} {
		_, err := os.Lstat(filepath.Join(dir, name))

		switch {
		case err == nil:
			return ReservationAuthorityInfo{}, ErrReservationAuthorityExists
		case !errors.Is(err, os.ErrNotExist):
			return ReservationAuthorityInfo{}, errors.Join(ErrReservationUnavailable, err)
		}
	}

	id, err := newReservationAuthorityID()
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	info := ReservationAuthorityInfo{Version: 1, ID: id, Directory: dir, PublicKeySHA256: fingerprint}

	payload, err := json.Marshal(info)
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	if len(payload) > maxReservationAuthorityBytes {
		return ReservationAuthorityInfo{}, ErrReservationUnavailable
	}

	header, err := authorityJournalHeader(info)
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	// The exclusive link arbitrates concurrent initializers.
	if err := publishReservationFile(dir, reservationAuthorityFile, payload); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ReservationAuthorityInfo{}, ErrReservationAuthorityExists
		}

		return ReservationAuthorityInfo{}, err
	}

	// From here on the marker exists and is never removed.
	if err := initializeReservationJournalWithHeader(dir, header); err != nil {
		return ReservationAuthorityInfo{}, errors.Join(ErrReservationStateUncertain, err)
	}

	return info, nil
}

func loadReservationAuthorityInfo(root string) (ReservationAuthorityInfo, error) {
	marker, info, err := openReservationAuthorityMarker(root)
	if err != nil {
		return ReservationAuthorityInfo{}, err
	}

	// Read-only use: closing cannot lose anything.
	_ = marker.Close()

	return info, nil
}

// openReservationAuthorityMarker returns the marker still locked. It accepts exactly the bytes the
// initializer wrote, for this directory: the re-encoding refuses unknown or duplicated fields and
// trailing content.
func openReservationAuthorityMarker(root string) (*os.File, ReservationAuthorityInfo, error) {
	dir, err := canonicalAuthorityDirectory(root)
	if err != nil {
		return nil, ReservationAuthorityInfo{}, err
	}

	file, err := openLockedReservationJournal(filepath.Join(dir, reservationAuthorityFile), false)
	if err != nil {
		return nil, ReservationAuthorityInfo{}, err
	}

	info, err := readReservationAuthorityMarker(file, dir)
	if err != nil {
		_ = file.Close()
		return nil, ReservationAuthorityInfo{}, err
	}

	return file, info, nil
}

func readReservationAuthorityMarker(file *os.File, dir string) (ReservationAuthorityInfo, error) {
	// A crash right after the marker was published can leave it, or its directory entry, unflushed.
	if err := file.Sync(); err != nil {
		return ReservationAuthorityInfo{}, errors.Join(ErrReservationUnavailable, err)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxReservationAuthorityBytes+1))
	if err != nil {
		return ReservationAuthorityInfo{}, errors.Join(ErrReservationUnavailable, err)
	}

	if len(data) == 0 || len(data) > maxReservationAuthorityBytes {
		return ReservationAuthorityInfo{}, ErrReservationAuthorityMismatch
	}

	var info ReservationAuthorityInfo
	if err := json.Unmarshal(data, &info); err != nil || !info.valid() || !sameAuthorityDirectory(info.Directory, dir) {
		return ReservationAuthorityInfo{}, ErrReservationAuthorityMismatch
	}

	canonical, err := json.Marshal(info)
	if err != nil || !bytes.Equal(data, canonical) {
		return ReservationAuthorityInfo{}, ErrReservationAuthorityMismatch
	}

	if err := syncReservationDirectory(dir); err != nil {
		return ReservationAuthorityInfo{}, errors.Join(ErrReservationUnavailable, err)
	}

	return info, nil
}

// sameAuthorityDirectory compares directory identity, not spelling: a case alias on a
// case-insensitive filesystem is the same authority; a copy elsewhere or a moved directory is not.
func sameAuthorityDirectory(recorded, dir string) bool {
	a, err := os.Stat(recorded)
	if err != nil {
		return false
	}

	b, err := os.Stat(dir)

	return err == nil && a.IsDir() && os.SameFile(a, b)
}

// OpenReservationAuthority opens a provisioned authority with the current controller key. A marker
// without its matching healthy journal is not a usable authority.
func OpenReservationAuthority(root string, signer LabSigner) (*ReservationAuthority, error) {
	fingerprint, err := reservationAuthorityFingerprint(signer)
	if err != nil {
		return nil, err
	}

	info, err := loadReservationAuthorityInfo(root)
	if err != nil {
		return nil, err
	}

	// There is no key rotation: a provisioned authority keeps its key.
	if info.PublicKeySHA256 != fingerprint {
		return nil, ErrReservationAuthorityMismatch
	}

	authority := &ReservationAuthority{info: info}
	if _, err := authority.List(); err != nil {
		return nil, err
	}

	return authority, nil
}

// reservationJournalSpec is the expected journal format and, in production, its authority.
type reservationJournalSpec struct {
	directory string
	header    string
	authority *ReservationAuthorityInfo
}

// legacyReservationJournal is the V1 journal, kept for internal tests only.
func legacyReservationJournal(dir string) reservationJournalSpec {
	return reservationJournalSpec{directory: dir, header: reservationJournalMagic}
}

func (a *ReservationAuthority) journal() (reservationJournalSpec, error) {
	if a == nil || !a.info.valid() {
		return reservationJournalSpec{}, ErrReservationUnavailable
	}

	header, err := authorityJournalHeader(a.info)
	if err != nil {
		return reservationJournalSpec{}, err
	}

	info := a.info

	return reservationJournalSpec{directory: info.Directory, header: header, authority: &info}, nil
}

// reservationJournalHandle is the locked journal and, for an authority, its marker, locked for the
// whole operation so the marker cannot change between its check and the journal's use.
type reservationJournalHandle struct {
	*os.File
	marker *os.File
}

func (h reservationJournalHandle) Close() error {
	err := h.File.Close()

	if h.marker != nil {
		_ = h.marker.Close()
	}

	return err
}

// open re-reads the marker before every operation (provisioning never modifies a valid one), then
// locks the journal while still holding the marker.
func (j reservationJournalSpec) open() (reservationJournalHandle, error) {
	path, err := reservationJournalPath(j.directory)
	if err != nil {
		return reservationJournalHandle{}, err
	}

	if j.authority == nil {
		file, err := openLockedReservationJournal(path, false)
		return reservationJournalHandle{File: file}, err
	}

	marker, current, err := openReservationAuthorityMarker(j.directory)
	if err != nil {
		return reservationJournalHandle{}, err
	}

	if current != *j.authority {
		_ = marker.Close()
		return reservationJournalHandle{}, ErrReservationAuthorityMismatch
	}

	file, err := openLockedReservationJournal(path, false)
	if err != nil {
		_ = marker.Close()
		return reservationJournalHandle{}, err
	}

	handle := reservationJournalHandle{File: file, marker: marker}

	// The marker's name must still be the file we hold.
	held, err := marker.Stat()
	if err == nil {
		var named os.FileInfo
		if named, err = os.Lstat(filepath.Join(j.directory, reservationAuthorityFile)); err == nil && !os.SameFile(held, named) {
			err = ErrReservationAuthorityMismatch
		}
	}

	if err != nil {
		_ = handle.Close()
		return reservationJournalHandle{}, errors.Join(ErrReservationAuthorityMismatch, err)
	}

	return handle, nil
}

func (j reservationJournalSpec) read(file *os.File) (reservationJournalState, error) {
	state, err := readReservationJournalWithHeader(file, j.header)
	if err != nil {
		return reservationJournalState{}, err
	}

	if j.authority != nil {
		for _, hold := range state.registry.byOwner {
			if hold.PublicKeySHA256 != j.authority.PublicKeySHA256 {
				return reservationJournalState{}, ErrReservationAuthorityMismatch
			}
		}
	}

	return state, nil
}

func (a *ReservationAuthority) List() ([]EgressReservation, error) {
	journal, err := a.journal()
	if err != nil {
		return nil, err
	}

	return inspectReservationJournalSpec(journal)
}
