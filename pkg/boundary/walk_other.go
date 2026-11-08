//go:build !windows

package boundary

// defaultNormBase is nil: outside Windows the walked spelling is canonical.
var defaultNormBase func(string) (string, error)

func isWindowsNameTooLong(error) bool { return false }
