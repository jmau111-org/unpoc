package main

import (
    "fmt"
    "os"
    "strconv"
    "syscall"
)

// meant for Linux
func main() {
    if len(os.Args) < 2 {
        fmt.Println("Please specify a process ID.")
        return
    }

    pid, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Println("Please specify a valid process ID.")
        return
    }

    err = syscall.PtraceAttach(pid)
    if err != nil {
        fmt.Println("Could not attach to process with ID", pid, ":", err)
        return
    }

    err = syscall.PtraceDetach(pid)
    if err != nil {
        fmt.Println("Could not detach from process with ID", pid, ":", err)
        return
    }

    fmt.Println("Process with ID", pid, "hidden.")
}
