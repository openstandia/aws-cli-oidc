package lib

import (
	"fmt"
	"os"
	"runtime"
)

var IsTraceEnabled bool

func Write(format string, msg ...interface{}) {
	fmt.Fprintf(os.Stderr, format, msg...)
}

func Writeln(format string, msg ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, msg...))
}

func Export(key string, value string) {
	var msg string
	if runtime.GOOS == "windows" {
		msg = fmt.Sprintf("set %s=%s\n", key, value)
	} else {
		msg = fmt.Sprintf("export %s=%s\n", key, value)
	}
	fmt.Fprint(os.Stdout, msg)
}

func Traceln(format string, msg ...interface{}) {
	if IsTraceEnabled {
		fmt.Fprintln(os.Stderr, fmt.Sprintf(format, msg...))
	}
}

func Exit(err error) {
	if err != nil {
		Writeln(err.Error())
	}
	os.Exit(1)
}
