# seccomp_unotify
A Golang-based syscall interception tool using Seccomp Notify as an alternative to ptrace

## Installation
Clone the repository
```
git clone https://github.com/robertmin1/seccomp_unotify
cd seccomp_unotify
go mod init main.go
go mod tidy
```

## Usage

```
go run main.go wget google.com
go run main.go firefox
```
