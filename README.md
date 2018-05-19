Q: What does this "wru" tool do?
A: "wru" tries to predict the behavior of a Windows executable without actually running the program.  It does this by statically obtaining about 20 metrics from the program using the Radare2 open source debugger to get those metrics.  The 20 or so metrics were the ones found to be subjectively most useful after trial and error with static analysis and spreadsheet analysis. Some of these metrics are simple, others are lengthy strings.  "wru" then refers to its datastore of similar metadata from all the other Windows programs it's looked at, and using a custom version of the Euclidean Distance algorithm, displays which other programs a given executable most closely resembles.  "wru" also predicts what broad areas of interesting functionality the target program will have (currently: Networking, Media, UI, Registry, Security, Crypto, Database) based on known libraries and educated guessing based upon keywords found in imports and functions.  Lastly, "wru" can provide estimates of specialized functionality using Bayes Theorem, in instances when a given target executable is not providing good metadata, or simply as another way to predict functionality.
  The idea is that by predicting the capabilities of an executable, and also by showing what other programs a new executable seems to resemble most closely (and how closely), one can predict runtime behavior to a useful degree.

Q:  Why?

A   The tool is fairly fast, performing its analysis in a few seconds on one executable. This can let one quickly decide if a given executable is interesting enough to warrant further investigation using behavioral analysis or debugging.


Q:  Does this really work?

A:  In the author's experience, yes.  I like to use it as a triage tool, often looping over files, to decide which one(s) are worth investing time to debug.  


Q: How does this "wru" tool do its work under the covers?

A: A longer answer, see below under the section about installing on Ubuntu.


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

** evolving...notes for using on OSX **

For SQLite3 on OSX, need to do this stuff:
  1) Build go-sqlite3 with libsqlite3 on OS X.
  2) Install sqlite3 from homebrew: `brew install sqlite3`
  3) Use `go build --tags "libsqlite3 darwin"`
========================

Q: How does this "wru" tool do its work?
A:  TODO..
