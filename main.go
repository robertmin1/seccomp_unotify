package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// SyscallHandler defines the handler function for a syscall notification.
type SyscallHandler func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)

func initSeccomp() chan<- struct{} {
	api, err := libseccomp.GetAPI()
	if err != nil {
		fmt.Println("Failed to get seccomp API level")
		os.Exit(1)
	} else if api < 5 {
		fmt.Printf("Need seccomp API level >= 5; it's currently %d\n", api)
		os.Exit(1)
	}

	fd, err := LoadFilter()
	if err != nil {
		fmt.Printf("Failed to load seccomp filter: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Seccomp filter loaded with notification FD: %v\n", fd)

	handlers := map[string]SyscallHandler{"connect": HandleConnect}

	stop, errChan := Handle(fd, handlers)
	go func() {
		for err := range errChan {
			fmt.Printf("Error in syscall monitoring: %v\n", err)
			os.Exit(1)
		}
	}()
	return stop
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: sockstrace <program> [args...]")
		os.Exit(1)
	}

	stop := initSeccomp()
	defer close(stop)

	runProgram(args[0], args[1:])
}

func runProgram(program string, args []string) {
	fmt.Printf("Executing program: %s\n", program)

	cmd := exec.Command(program, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error executing program: %v\n", err)
		os.Exit(1)
	}
}

func LoadFilter() (libseccomp.ScmpFd, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return 0, err
	}

	syscallID, err := libseccomp.GetSyscallFromName("connect")
	if err != nil {
		return 0, err
	}

	if err := filter.AddRule(syscallID, libseccomp.ActNotify); err != nil {
		return 0, err
	}

	if err := filter.Load(); err != nil {
		return 0, err
	}

	fd, err := filter.GetNotifFd()
	if err != nil {
		return 0, err
	}
	return fd, nil
}

func Handle(fd libseccomp.ScmpFd, handlers map[string]SyscallHandler) (chan<- struct{}, <-chan error) {
	stop := make(chan struct{})
	errChan := make(chan error)

	go func() {
		for {
			req, err := libseccomp.NotifReceive(fd)
			if err != nil {
				if err == syscall.ENOENT {
					fmt.Printf("Notification no longer valid: %v\n", err)
					continue
				}
				fmt.Printf("Failed to receive notification: %v\n", err)
				errChan <- err
				if err == unix.ECANCELED {
					return
				}
				continue
			}

			select {
			case <-stop:
				_ = libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
					ID:    req.ID,
					Error: int32(unix.EPERM),
					Val:   0,
					Flags: 0,
				})
				return
			default:
			}

			err = libseccomp.NotifIDValid(fd, req.ID)
			if err != nil {
				fmt.Printf("Failed to validate notification ID: %v\n", err)
			}

			go func(req *libseccomp.ScmpNotifReq) {
				syscallName, _ := req.Data.Syscall.GetName()
				handler, ok := handlers[syscallName]
				if !ok {
					fmt.Printf("Unknown syscall: %s (PID: %d)\n", syscallName, req.Pid)
					_ = libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
						ID:    req.ID,
						Error: int32(unix.ENOSYS),
						Val:   0,
						Flags: 0,
					})
					return
				}

				val, errno, flags := handler(fd, req)
				if err := libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
					ID:    req.ID,
					Error: errno,
					Val:   val,
					Flags: flags,
				}); err != nil {
					errChan <- err
				}
			}(req)
		}
	}()
	return stop, errChan
}

func HandleConnect(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	fmt.Printf("Intercepted 'connect' syscall from PID %d\n", req.Pid)
	return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}
