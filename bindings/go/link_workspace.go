//go:build aster_workspace

package aster

/*
#cgo linux LDFLAGS: -L${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/debug
#cgo darwin LDFLAGS: -L${SRCDIR}/../../target/debug -Wl,-rpath,${SRCDIR}/../../target/debug
*/
import "C"
