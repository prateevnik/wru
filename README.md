** evolving... **

Need at least Go version 1.8.1, to void strange "signal:killed" error when using SQLite libraries from mattn.

For SQLite3, may need to do this stuff:

* Want to build go-sqlite3 with libsqlite3 on OS X.

    Install sqlite3 from homebrew: `brew install sqlite3`

    Use `go build --tags "libsqlite3 darwin"`
