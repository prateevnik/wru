** evolving... **

For SQLite3 on OSX, may need to do this stuff:

* Build go-sqlite3 with libsqlite3 on OS X.

    Install sqlite3 from homebrew: `brew install sqlite3`

    Use `go build --tags "libsqlite3 darwin"`

Installing wru on Ubuntu 16.04:
=========================
- install Go. Get latest for Linux from golang.org, or at least Go version 1.8.1 (to avoid "signal:killed" error when using SQLite libraries from mattn)
- per defaults from golang.org download, in .profile put:
     export PATH=$PATH:/usr/local/go/bin
- set $GOPATH in .profile, typical is as follows:
     export GOPATH=$HOME/src/go
- if needed create stuff:  mkdir -p ~/src/go/src  # this is assuming you want ~/src for other things, like ~/src/python, ~src/C++ etc.
- do 'sudo apt-get install  git'
####- don't apt-get install radare2, the package won't work right for us.
- install source for Radare2 (version 2.4.0 as of February 2018): cd $HOME/src; git clone https://github.com/radare/radare2.git
- compile and install Radare2, 'cd radare2', then do 'sys/install.sh', then 'sys/user.sh'
- cd $GOPATH
- do 'go get github.com/mattn/go-sqlite3'
- from $HOME/src/go/src, do 'git clone https://github.com/prateevnik/wru.git'
- mkdir $HOME/.wru
- from cloned wru project, move or copy the SQLite file 'data.db' to $HOME/.wru/data.db
- OPTIONAL: create config file for specifying SQLite db location, can be shared
     create $HOME/.wru/wru.conf, with an entry like "database=/var/local/wru".  Don't put 'data.db' in that config entry, it's assumed.
- While in some working directory *not* named "wru", do 'go build wru'.  For example: "cd $HOME/bin;  go build wru" (if $HOME/bin is in your normal path)

The executable "wru" should now be present in your current working directory. Run it without arguments to get help.
Run the "wru" executable with no arguments for help on options.  Run it with a Windows program as a target like "./wru zip.exe" to start populating the SQLite db with data.
The more Windows programs you run 'wru' against, the more useful the results become.
