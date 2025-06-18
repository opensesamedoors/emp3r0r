package agentutils

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// WriteFileSecure is a centralized file writing function for agent operations.
// This function wraps all file writing operations to allow for future modifications
// such as encryption, steganography, or other security enhancements.
func WriteFileSecure(filename string, data []byte, perm os.FileMode) error {
	// Future enhancements can be added here:
	// - File encryption before writing
	// - Steganography to hide files
	// - Anti-forensics techniques
	// - Atomic writes with temporary files
	// - Logging for debugging (but be careful with OpSec)

	logging.Debugf("Writing %d bytes to %s with permissions %o", len(data), filename, perm)

	// Currently just wraps os.WriteFile, but can be enhanced later
	return os.WriteFile(filename, data, perm)
}

// CreateFileSecure is a centralized file creation function for agent operations.
// This function wraps file creation operations to allow for future modifications.
func CreateFileSecure(filename string) (*os.File, error) {
	logging.Debugf("Creating file %s", filename)

	// Future enhancements can be added here:
	// - Hidden file attributes
	// - Special file creation flags
	// - Anti-forensics techniques

	return os.Create(filename)
}

// OpenFileSecure is a centralized file opening function for agent operations.
// This function wraps file opening operations to allow for future modifications.
func OpenFileSecure(filename string, flag int, perm os.FileMode) (*os.File, error) {
	logging.Debugf("Opening file %s with flags %d and permissions %o", filename, flag, perm)

	// Future enhancements can be added here:
	// - Special file opening flags
	// - Anti-forensics techniques
	// - File locking mechanisms

	return os.OpenFile(filename, flag, perm)
}
