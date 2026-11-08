package boundary

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
)

// ErrResolutionLimit is matched (errors.Is) by every error that means a path was not resolved
// because a resolution limit was reached: ErrPathTooLong and ErrWorkBudgetExhausted. Such a
// path is unverifiable. Callers must fail closed on it (ask, or treat the path as sensitive
// and not contained), never treat it as contained or safe.
var ErrResolutionLimit = errors.New("path resolution limit reached")

// limitError is a sentinel that also matches ErrResolutionLimit.
type limitError struct{ msg string }

func (e *limitError) Error() string        { return e.msg }
func (e *limitError) Is(target error) bool { return target == ErrResolutionLimit }

// ErrWorkBudgetExhausted is returned when resolving a path would exceed the work budget of
// the current evaluation (see BeginEvaluation and WorkBudget).
var ErrWorkBudgetExhausted error = &limitError{"path resolution work budget exhausted"}

// WorkBudget bounds the filesystem work spent resolving paths for one evaluation. Each lookup
// (Lstat or Readlink, and on Windows the final normalization) is charged the length of the path
// it passes to the OS, in ResolvePathLength units (bytes; UTF-16 code units on Windows), since
// the OS walks that path component by component: resolving an existing path of n components
// costs about n times its length (half its length times its depth). The budget is separate
// from the per-path length limit (MaxResolvePathLength). On the slowest shape (one-letter
// components) 4 MiB of lookups take about 0.2 s on Linux. It fits any single path within the
// length limit whose components average more than two bytes; an ordinary path of a few hundred
// bytes costs a few kilobytes, and prefixes already resolved in the evaluation cost nothing.
const WorkBudget = 4 << 20

// maxLinksWalked matches filepath.EvalSymlinks.
const maxLinksWalked = 255

// Test seams for the filesystem calls made by the walk.
var (
	lstat    = os.Lstat
	readlink = os.Readlink
	// normalize gives a symlink-free path its canonical spelling. On Windows that is
	// filepath.EvalSymlinks (letter case, short names), as before the walk was metered.
	normalize = defaultNormalize
)

func defaultNormalize(p string) (string, error) {
	if runtime.GOOS == "windows" {
		return filepath.EvalSymlinks(p)
	}
	return p, nil
}

// evaluation is the shared state of the path resolutions made for one gate evaluation: the
// remaining work budget and the resolutions of path prefixes already walked.
type evaluation struct {
	remaining int64
	prefixes  map[string]*prefixNode // keyed by volume, including its root separator
	normal    map[string]string      // normalize results by walked path
}

// prefixNode is a trie of path components: the resolution of every prefix of an input path
// that has been walked completely.
type prefixNode struct {
	resolved string
	children map[string]*prefixNode
}

func (n *prefixNode) child(component, resolved string) *prefixNode {
	if n.children == nil {
		n.children = make(map[string]*prefixNode)
	}
	c := n.children[component]
	if c == nil {
		c = &prefixNode{resolved: resolved}
		n.children[component] = c
	}
	return c
}

func newEvaluation() *evaluation {
	return &evaluation{
		remaining: WorkBudget,
		prefixes:  make(map[string]*prefixNode),
		normal:    make(map[string]string),
	}
}

var (
	evalMu sync.Mutex
	active *evaluation
)

// BeginEvaluation starts a shared resolution scope: until the returned function is called,
// every path resolved by this package (CanonicalizePath, Resolver, EvalSymlinks) draws on one
// work budget of WorkBudget and reuses the prefixes already resolved. Call it once per
// tool call evaluated, so the checks that resolve the call's paths (anti-tampering, sensitive
// files, boundary, trusted-command arguments, taint) cannot each spend a full budget. A call
// made while a scope is active joins it and returns a no-op. Outside any scope, each resolution
// gets a budget of its own.
//
// The scope is process-wide: the gate evaluates one call per process. Evaluations running
// concurrently in one process would share the budget, which can only make them ask more.
func BeginEvaluation() (end func()) {
	evalMu.Lock()
	defer evalMu.Unlock()
	if active != nil {
		return func() {}
	}
	e := newEvaluation()
	active = e
	return func() {
		evalMu.Lock()
		defer evalMu.Unlock()
		if active == e {
			active = nil
		}
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

func (e *evaluation) charge(n int) error {
	if int64(n) > e.remaining {
		e.remaining = 0
		return ErrWorkBudgetExhausted
	}
	e.remaining -= int64(n)
	return nil
}

// EvalSymlinks is filepath.EvalSymlinks for an absolute path, metered by the evaluation's work
// budget and the path length limit: it fails when any component does not exist, and with an
// error matching ErrResolutionLimit when a limit is reached.
func EvalSymlinks(path string) (string, error) {
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		path = abs
	}
	clean := filepath.Clean(path)
	if err := checkPathLength(clean); err != nil {
		return "", err
	}
	return withEvaluation(func(e *evaluation) (string, error) {
		return e.resolve(clean, true)
	})
}

// resolve evaluates symlinks in an absolute, cleaned path, one component at a time as the OS
// does (the walk of filepath.EvalSymlinks), charging each lookup to the budget. When strict is
// false and a component cannot be resolved (a file about to be created), the deepest ancestor
// that resolves is returned with the rest of the path appended as written.
//
// Every prefix of the input that is resolved completely is recorded, so a later path sharing
// it starts its walk there: words of one command under the same deep directory cost one walk.
func (e *evaluation) resolve(path string, strict bool) (string, error) {
	sep := string(filepath.Separator)
	volLen := len(filepath.VolumeName(path))
	if volLen < len(path) && os.IsPathSeparator(path[volLen]) {
		volLen++
	}
	rootKey := path[:volLen]
	node := e.prefixes[rootKey]
	if node == nil {
		node = &prefixNode{resolved: rootKey}
		e.prefixes[rootKey] = node
	}

	// Start after the deepest prefix already resolved. good is where the unresolved part
	// of the input begins; goodDest is the resolution of the input before it.
	good, goodDest := volLen, node.resolved
	for start := volLen; start < len(path); {
		end := start
		for end < len(path) && !os.IsPathSeparator(path[end]) {
			end++
		}
		next := node.children[path[start:end]]
		if next == nil {
			break
		}
		node, good, goodDest = next, end, next.resolved
		start = end + 1
	}

	// The walk below is filepath's walkSymlinks over walk (the unresolved input, possibly with
	// symlink targets spliced in front of it). origStart is where the input's own suffix starts
	// in walk; components before it come from symlink targets.
	walk := path[good:]
	origStart := 0
	inputIndex := func(i int) int { return len(path) - len(walk) + i }
	dest := goodDest
	vol, vLen := volumePrefix(dest)
	pending := "" // an input component that is a symlink still being resolved
	linksWalked := 0

	// settle records the input components resolved completely once the walk reaches pos.
	settle := func(pos int) {
		if pending != "" && pos >= origStart {
			node = node.child(pending, dest)
			good, goodDest = inputIndex(origStart), dest
			pending = ""
		}
	}
	fail := func(err error) (string, error) {
		if strict || errors.Is(err, ErrResolutionLimit) {
			return "", err
		}
		rest := path[good:]
		for len(rest) > 0 && os.IsPathSeparator(rest[0]) {
			rest = rest[1:]
		}
		base, nerr := e.normalized(goodDest)
		if nerr != nil {
			return "", nerr
		}
		if rest == "" {
			return filepath.Clean(base), nil
		}
		if len(base) > 0 && os.IsPathSeparator(base[len(base)-1]) {
			return filepath.Clean(base + rest), nil
		}
		return filepath.Clean(base + sep + rest), nil
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
		fromInput := start >= origStart && pending == ""

		if component == "." {
			settle(end)
			continue
		}
		if component == ".." {
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
			settle(end)
			continue
		}

		if len(dest) > len(filepath.VolumeName(dest)) && !os.IsPathSeparator(dest[len(dest)-1]) {
			dest += sep
		}
		dest += component

		if err := e.charge(ResolvePathLength(dest)); err != nil {
			return "", err
		}
		fi, err := lstat(dest)
		if err != nil {
			return fail(err)
		}

		if fi.Mode()&fs.ModeSymlink == 0 {
			if fromInput {
				node = node.child(component, dest)
				good, goodDest = inputIndex(end), dest
			} else {
				settle(end)
			}
			if !fi.Mode().IsDir() && end < len(walk) {
				return fail(syscall.ENOTDIR)
			}
			continue
		}

		linksWalked++
		if linksWalked > maxLinksWalked {
			return fail(errors.New("too many links"))
		}
		if err := e.charge(ResolvePathLength(dest)); err != nil {
			return "", err
		}
		link, err := readlink(dest)
		if err != nil {
			return fail(err)
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
	return e.normalized(filepath.Clean(dest))
}

// volumePrefix returns the volume of an absolute path including its root separator, and its length.
func volumePrefix(p string) (string, int) {
	v := len(filepath.VolumeName(p))
	if v < len(p) && os.IsPathSeparator(p[v]) {
		v++
	}
	return p[:v], v
}

// normalized applies normalize to a walked path, once per path in the evaluation, charging
// a walk of it to the budget when normalize touches the filesystem.
func (e *evaluation) normalized(p string) (string, error) {
	if got, ok := e.normal[p]; ok {
		return got, nil
	}
	if runtime.GOOS == "windows" {
		if err := e.charge(walkCost(p)); err != nil {
			return "", err
		}
	}
	got, err := normalize(p)
	if err != nil {
		got = p // a race or an unsupported path: keep the walked spelling
	}
	got = filepath.Clean(got)
	e.normal[p] = got
	return got, nil
}

// walkCost is what looking up every prefix of p costs: the sum of the prefix lengths, in
// ResolvePathLength units.
func walkCost(p string) int {
	cost, length := 0, 0
	if runtime.GOOS != "windows" {
		for i := 1; i < len(p); i++ {
			if os.IsPathSeparator(p[i]) {
				cost += i
			}
		}
		return cost + len(p)
	}
	for i, r := range p {
		if i > 0 && os.IsPathSeparator(p[i]) {
			cost += length
		}
		length += utf16Units(r)
	}
	return cost + length
}
