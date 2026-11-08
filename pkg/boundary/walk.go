package boundary

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// ErrResolutionLimit is matched (errors.Is) by every error that means a path was not resolved
// because a resolution limit was reached: ErrPathTooLong, ErrWorkBudgetExhausted and
// ErrUnverifiablePath. Such a
// path is unverifiable. Callers must fail closed on it (ask, or treat the path as sensitive
// and not contained), never treat it as contained or safe.
var ErrResolutionLimit = errors.New("path resolution limit reached")

// limitError is a sentinel that also matches ErrResolutionLimit.
type limitError struct{ msg string }

func (e *limitError) Error() string        { return e.msg }
func (e *limitError) Is(target error) bool { return target == ErrResolutionLimit }

// ErrUnverifiablePath is returned, wrapped, for a Windows extended-length or device
// namespace path (\\?\, \\.\, \??\, in either slash spelling) with a "." or ".."
// component. Win32 passes such a path to the filesystem without collapsing "." and "..", so
// cleaning it lexically, as the walk does for ordinary Windows paths, could name another file
// than the one the OS opens. It matches ErrResolutionLimit, so every caller fails closed on it.
var ErrUnverifiablePath error = &limitError{"extended or device namespace path with . or .. components cannot be verified"}

// ErrWorkBudgetExhausted is returned when resolving a path would exceed the work budget of
// the current evaluation (see BeginEvaluation and WorkBudget).
var ErrWorkBudgetExhausted error = &limitError{"path resolution work budget exhausted"}

// WorkBudget bounds the filesystem work spent resolving paths for one evaluation. Each lookup
// (Lstat or Readlink) is charged the length of the path it passes to the OS, in
// ResolvePathLength units (bytes; UTF-16 code units on Windows), since the OS walks that path
// component by component: resolving an existing path of n components costs about n times its
// length (half its length times its depth). The budget is separate from the per-path length
// limit (MaxResolvePathLength). On the slowest shape (one-letter components) 4 MiB of lookups
// take about 0.2 s on Linux. It fits any single path within the length limit whose components
// average more than two bytes; an ordinary path of a few hundred bytes costs a few kilobytes,
// and prefixes already resolved in the evaluation cost nothing.
//
// On Windows every resolved path is also normalized (letter case, short names), one
// FindFirstFile lookup per component, as filepath.EvalSymlinks does. Normalization is cached
// per prefix like the walk and charged the same way, to a second budget of the same size: it
// never looks up more than the walk did, so a path that fits the walk budget on another OS
// fits on Windows too.
const WorkBudget = 4 << 20

// workBudget is WorkBudget; tests lower it to exercise exhaustion without deep trees.
var workBudget int64 = WorkBudget

// maxLinksWalked matches filepath.EvalSymlinks.
const maxLinksWalked = 255

// Test seams for the filesystem calls made by the walk.
var (
	lstat    = os.Lstat
	readlink = os.Readlink
	// normBase returns the on-disk spelling of the last component of a symlink-free absolute
	// path: on Windows, FindFirstFile, as filepath.EvalSymlinks normalizes (letter case,
	// short names). nil elsewhere: the walked spelling is canonical.
	normBase = defaultNormBase
)

// evaluation is the shared state of the path resolutions made for one gate evaluation: the
// remaining work budgets and the resolutions of path prefixes already walked.
type evaluation struct {
	remaining     int64
	normRemaining int64
	prefixes      map[string]*prefixNode // keyed by volume, including its root separator
	normal        map[string]string      // normalized spellings by walked (cleaned) prefix
}

// prefixNode is a trie of input path components, as written (".." included; empty and "."
// components, which name the same directory, are skipped): the resolution of every prefix of
// an input path that has been walked completely. A node for a non-directory is only reused
// at the end of a path: the OS fails a lookup that continues below a file (ENOTDIR).
type prefixNode struct {
	resolved string
	dir      bool
	children map[string]*prefixNode
}

func (n *prefixNode) child(component, resolved string, dir bool) *prefixNode {
	if n.children == nil {
		n.children = make(map[string]*prefixNode)
	}
	c := n.children[component]
	if c == nil {
		c = &prefixNode{resolved: resolved, dir: dir}
		n.children[component] = c
	}
	return c
}

func newEvaluation() *evaluation {
	return &evaluation{
		remaining:     workBudget,
		normRemaining: workBudget,
		prefixes:      make(map[string]*prefixNode),
		normal:        make(map[string]string),
	}
}

var (
	evalMu      sync.Mutex
	active      *evaluation
	activeHolds int
)

// BeginEvaluation starts a shared resolution scope: until the returned function is called,
// every path resolved by this package (CanonicalizePath, Resolver, EvalSymlinks) draws on one
// work budget of WorkBudget and reuses the prefixes already resolved. Call it once per
// tool call evaluated, so the checks that resolve the call's paths (anti-tampering, sensitive
// files, boundary, trusted-command arguments, taint) cannot each spend a full budget. A call
// made while a scope is active joins it; the scope ends when the last holder calls its end
// function (each end function takes effect once). Outside any scope, each resolution gets a
// budget of its own.
//
// The scope is process-wide. The CLI evaluates one tool call per process, so there is only
// ever one evaluation. Evaluations overlapping in one process would join one scope: they
// share one budget and one prefix cache until the last of them ends, which can only make
// them ask more, never give one of them a fresh budget.
func BeginEvaluation() (end func()) {
	evalMu.Lock()
	defer evalMu.Unlock()
	if active == nil {
		active = newEvaluation()
	}
	activeHolds++
	var once sync.Once
	return func() {
		once.Do(func() {
			evalMu.Lock()
			defer evalMu.Unlock()
			activeHolds--
			if activeHolds == 0 {
				active = nil
			}
		})
	}
}

// withEvaluation runs fn with the active evaluation, or a fresh one outside any scope.
func withEvaluation(fn func(e *evaluation) (string, error)) (string, error) {
	evalMu.Lock()
	defer evalMu.Unlock()
	e := active
	if e == nil {
		e = newEvaluation()
	}
	return fn(e)
}

func charge(remaining *int64, n int) error {
	if int64(n) > *remaining {
		*remaining = 0
		return ErrWorkBudgetExhausted
	}
	*remaining -= int64(n)
	return nil
}

// EvalSymlinks is filepath.EvalSymlinks, metered by the evaluation's work budget and the path
// length limit: it fails when any component does not exist, and with an error matching
// ErrResolutionLimit when a limit is reached. A relative path is resolved from the current
// directory. The result is absolute.
//
// The path is walked as written: like the OS on Unix, a ".." applies to what the component
// before it resolved to, so "link/../f" is "f" next to the symlink's target, not next to the
// symlink. On Windows, where Win32 itself removes "." and ".." lexically before the
// filesystem sees the path, the path is cleaned first, as the OS does.
func EvalSymlinks(path string) (string, error) {
	abs, err := absInput(path)
	if err != nil {
		return "", err
	}
	return withEvaluation(func(e *evaluation) (string, error) {
		return e.resolve(abs, true)
	})
}

// JoinPath returns p, made absolute against base when it is relative, without cleaning it:
// ".." components must stay for the walk to apply them where the OS does (after the
// symlink before them is followed). An absolute p is returned as is.
func JoinPath(base, p string) string {
	if filepath.IsAbs(p) || base == "" {
		return p
	}
	if os.IsPathSeparator(base[len(base)-1]) {
		return base + p
	}
	return base + string(filepath.Separator) + p
}

// absInput makes path absolute for the walk, checking the length limit before and after.
// The check before is conservative: making a path absolute never shortens it.
func absInput(path string) (string, error) {
	if err := checkPathLength(path); err != nil {
		return "", err
	}
	var abs string
	if runtime.GOOS == "windows" {
		if hasNamespaceDotComponent(path) {
			return "", fmt.Errorf("%w: %s", ErrUnverifiablePath, path)
		}
		// Win32 resolves "." and ".." lexically in ordinary paths, so cleaning matches the OS.
		a, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		abs = filepath.Clean(a)
	} else if filepath.IsAbs(path) {
		abs = path
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = JoinPath(cwd, path)
	}
	if err := checkPathLength(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// hasNamespaceDotComponent reports whether p, read as a Windows path, is in the extended-length
// or device namespace (\\?\, \\.\ or \??\, with either slash) and has a "." or ".."
// component after the prefix. Windows does not collapse those components in such a path.
func hasNamespaceDotComponent(p string) bool {
	if len(p) < 4 {
		return false
	}
	prefix := strings.ReplaceAll(p[:4], "/", `\`)
	if prefix != `\\?\` && prefix != `\\.\` && prefix != `\??\` {
		return false
	}
	for _, c := range strings.FieldsFunc(p[4:], func(r rune) bool { return r == '/' || r == '\\' }) {
		if c == "." || c == ".." {
			return true
		}
	}
	return false
}

// errTooLongLookup is the error for a lookup path over the limit, which a symlink target
// spliced into the walk can produce from a short input.
func errTooLongLookup(p string) error {
	return fmt.Errorf("%w: a lookup of length %d, limit %d", ErrPathTooLong, ResolvePathLength(p), MaxResolvePathLength())
}

// isNameTooLong reports an OS error for a path or name over the OS limit. It must not be
// mistaken for a missing component: the OS follows symlinks without that limit.
func isNameTooLong(err error) bool {
	return errors.Is(err, syscall.ENAMETOOLONG) || isWindowsNameTooLong(err)
}

// resolve evaluates symlinks in path, an absolute path as written (not cleaned), one
// component at a time as the OS does (the walk of filepath.EvalSymlinks), charging each
// lookup to the budget.
//
// When strict is false, a component that does not exist (a file about to be created) and
// everything after it is taken as written, as directories to be created: later components are appended without lookups, and
// a ".." removes the last of them, so "missing/../link" still follows link. A dangling
// symlink therefore resolves to its target, where writing through it creates the file.
// Resolution limits and every other lookup failure (a file followed by more components, a
// symlink loop, EACCES) are errors in both modes: such a path is unverifiable.
//
// Every prefix of the input that is resolved completely is recorded, so a later path sharing
// it starts its walk there: words of one command under the same deep directory cost one walk.
func (e *evaluation) resolve(path string, strict bool) (string, error) {
	sep := string(filepath.Separator)
	rootKey, volLen := volumePrefix(path)
	node := e.prefixes[rootKey]
	if node == nil {
		node = &prefixNode{resolved: rootKey, dir: true}
		e.prefixes[rootKey] = node
	}

	// Start after the deepest prefix already resolved.
	good := volLen
	for start := volLen; start < len(path); {
		for start < len(path) && os.IsPathSeparator(path[start]) {
			start++
		}
		end := start
		for end < len(path) && !os.IsPathSeparator(path[end]) {
			end++
		}
		if end == start {
			break // trailing separators after a directory
		}
		if component := path[start:end]; component != "." {
			next := node.children[component]
			if next == nil || (!next.dir && end < len(path)) {
				break
			}
			node = next
		}
		good, start = end, end
	}

	// The walk below is filepath's walkSymlinks over walk (the unresolved input, possibly with
	// symlink targets spliced in front of it). origStart is where the input's own suffix starts
	// in walk; components before it come from symlink targets.
	walk := path[good:]
	origStart := 0
	dest := node.resolved
	destDir := node.dir
	vol, vLen := volumePrefix(dest)
	pending := "" // an input component that is a symlink still being resolved
	linksWalked := 0
	recording := true
	// missing holds, for each component appended without a lookup (non-strict mode), the
	// length of dest before it.
	var missing []int

	// settle records the input component pending once the walk reaches pos.
	settle := func(pos int) {
		if recording && pending != "" && pos >= origStart {
			node = node.child(pending, dest, destDir)
			pending = ""
		}
	}
	// giveUp ends lookups at the component just appended to dest (non-strict mode).
	giveUp := func(before int) {
		recording, pending = false, ""
		missing = append(missing, before)
	}

	for start, end := 0, 0; start < len(walk); start = end {
		settle(start)
		for start < len(walk) && os.IsPathSeparator(walk[start]) {
			start++
		}
		end = start
		for end < len(walk) && !os.IsPathSeparator(walk[end]) {
			end++
		}
		if end == start {
			break
		}
		component := walk[start:end]
		fromInput := recording && start >= origStart && pending == ""

		if component == "." {
			settle(end)
			continue
		}
		if component == ".." {
			if n := len(missing); n > 0 {
				dest = dest[:missing[n-1]]
				missing = missing[:n-1]
				continue
			}
			r := len(dest) - 1
			for r >= vLen && !os.IsPathSeparator(dest[r]) {
				r--
			}
			if r < vLen || dest[r+1:] == ".." {
				if len(dest) > vLen {
					dest += sep
				}
				dest += ".."
			} else {
				dest = dest[:r]
			}
			destDir = true
			if fromInput {
				node = node.child("..", dest, true)
			}
			settle(end)
			continue
		}

		before := len(dest)
		if len(dest) > len(filepath.VolumeName(dest)) && !os.IsPathSeparator(dest[len(dest)-1]) {
			dest += sep
		}
		dest += component
		if len(missing) > 0 {
			missing = append(missing, before)
			continue
		}

		if checkPathLength(dest) != nil {
			return "", errTooLongLookup(dest)
		}
		if err := charge(&e.remaining, ResolvePathLength(dest)); err != nil {
			return "", err
		}
		fi, err := lstat(dest)
		if err != nil {
			if isNameTooLong(err) {
				return "", errTooLongLookup(dest)
			}
			// Only a name that does not exist is one to be created; any other failure
			// (EACCES, ELOOP, ENOTDIR, ...) leaves the path unverifiable.
			if strict || !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			giveUp(before)
			continue
		}

		if fi.Mode()&fs.ModeSymlink == 0 {
			if !fi.Mode().IsDir() && end < len(walk) {
				return "", syscall.ENOTDIR
			}
			destDir = fi.Mode().IsDir()
			if fromInput {
				node = node.child(component, dest, destDir)
			} else {
				settle(end)
			}
			continue
		}

		linksWalked++
		if linksWalked > maxLinksWalked {
			return "", errors.New("EvalSymlinks: too many links")
		}
		if err := charge(&e.remaining, ResolvePathLength(dest)); err != nil {
			return "", err
		}
		link, err := readlink(dest)
		if err != nil {
			if isNameTooLong(err) {
				return "", errTooLongLookup(dest)
			}
			return "", err
		}
		if fromInput {
			pending = component
		}

		if end >= origStart {
			origStart = len(link)
		} else {
			origStart = len(link) + origStart - end
		}
		walk = link + walk[end:]
		destDir = true

		if v := len(filepath.VolumeName(link)); v > 0 {
			if v < len(link) && os.IsPathSeparator(link[v]) {
				v++
			}
			vol, vLen = link[:v], v
			dest = vol
			end = v
		} else if len(link) > 0 && os.IsPathSeparator(link[0]) {
			vol, vLen = link[:1], 1
			dest = vol
			end = 1
		} else {
			r := len(dest) - 1
			for r >= vLen && !os.IsPathSeparator(dest[r]) {
				r--
			}
			if r < vLen {
				dest = vol
			} else {
				dest = dest[:r]
			}
			end = 0
		}
	}
	settle(len(walk)) // len(walk) >= origStart, so a pending symlink is recorded

	if len(missing) == 0 {
		return e.normalized(filepath.Clean(dest))
	}
	// Normalize the part that exists; the rest is plain names (no "." or "..") as written.
	base, err := e.normalized(filepath.Clean(dest[:missing[0]]))
	if err != nil {
		return "", err
	}
	rest := dest[missing[0]:]
	for len(rest) > 0 && os.IsPathSeparator(rest[0]) {
		rest = rest[1:]
	}
	if len(base) > 0 && os.IsPathSeparator(base[len(base)-1]) {
		return filepath.Clean(base + rest), nil
	}
	return filepath.Clean(base + sep + rest), nil
}

// volumePrefix returns the volume of an absolute path including its root separator, and its length.
func volumePrefix(p string) (string, int) {
	v := len(filepath.VolumeName(p))
	if v < len(p) && os.IsPathSeparator(p[v]) {
		v++
	}
	return p[:v], v
}

// normalized returns the canonical spelling of p, a cleaned, symlink-free absolute path. On
// Windows that is what filepath.EvalSymlinks returns for it (each component's on-disk
// spelling), built one prefix at a time and cached per prefix, so words under one deep
// directory normalize it once; each FindFirstFile is charged to the normalization budget.
// Elsewhere p is canonical already.
func (e *evaluation) normalized(p string) (string, error) {
	if normBase == nil {
		return p, nil
	}
	if got, ok := e.normal[p]; ok {
		return got, nil
	}
	// Collect the prefixes not yet normalized, deepest first.
	var todo []string
	q := p
	for {
		if _, ok := e.normal[q]; ok {
			break
		}
		vol := filepath.VolumeName(q)
		if rest := q[len(vol):]; rest == "" || rest == "." || rest == `\` || rest == "/" || baseIsDotDot(q) {
			e.normal[q] = normVolumeName(vol) + rest
			break
		}
		todo = append(todo, q)
		q = filepath.Dir(q)
	}
	for i := len(todo) - 1; i >= 0; i-- {
		cur := todo[i]
		parent := e.normal[filepath.Dir(cur)]
		if err := charge(&e.normRemaining, ResolvePathLength(cur)); err != nil {
			return "", err
		}
		name, err := normBase(cur)
		if err != nil {
			// Without the on-disk spelling, a short-name alias cannot be recognized: fail,
			// and cache nothing for this prefix or the ones below it.
			if isNameTooLong(err) {
				return "", errTooLongLookup(cur)
			}
			return "", err
		}
		if len(parent) > 0 && os.IsPathSeparator(parent[len(parent)-1]) {
			e.normal[cur] = parent + name
		} else {
			e.normal[cur] = parent + string(filepath.Separator) + name
		}
	}
	return e.normal[p], nil
}

func baseIsDotDot(p string) bool {
	i := strings.LastIndexAny(p, `/\`)
	return p[i+1:] == ".."
}

// normVolumeName is filepath's: a drive letter is upper-cased, a UNC volume kept.
func normVolumeName(p string) string {
	volume := filepath.VolumeName(p)
	if len(volume) > 2 {
		return volume
	}
	return strings.ToUpper(volume)
}

// SetWorkBudgetForTesting sets the work budget of evaluations begun afterwards, so tests can
// exhaust it without trees too deep for every platform's path limit, and returns a function
// restoring it. Tests only.
func SetWorkBudgetForTesting(n int64) (restore func()) {
	evalMu.Lock()
	defer evalMu.Unlock()
	old := workBudget
	workBudget = n
	return func() {
		evalMu.Lock()
		defer evalMu.Unlock()
		workBudget = old
	}
}
