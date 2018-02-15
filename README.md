** evolving... **

Need at least Go version 1.8.1, to void strange "signal:killed" error when using SQLite libraries from mattn.

For SQLite3, may need to do this stuff:

* Want to build go-sqlite3 with libsqlite3 on OS X.

    Install sqlite3 from homebrew: `brew install sqlite3`

    Use `go build --tags "libsqlite3 darwin"`

Installing wru on Debian:
=========================
- install Go, don't get the default package for Go 1.3.  Get latest for Linux from golang.org, or at least Go version 1.8.1
- per defaults from golang.org download, in .profile put:
     export PATH=$PATH:/usr/local/go/bin
- set $GOPATH in environment, probably in .profile:
     export GOPATH=$HOME/src/go

- if needed create stuff:  mkdir -p ~src/go/src
- cd $GOPATH
- do 'sudo apt-get install radare2 git'
- do 'go get github.com/mattn/go-sqlite3'
- git clone https://github.com/prateevnik/wru.git
- mkdir -p $HOME/.wru
- from cloned wru project, move SQLite file 'data.db' to $HOME/.wru/data.db
- OPTIONAL: create config file for specifying SQLite db location, can be shared
     create $HOME/.wru/wru.conf, with an entry like "db=/some/location/for/shared/data.db"
- do 'go build wru'
