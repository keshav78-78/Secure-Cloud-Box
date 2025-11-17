package store

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type FileMeta struct {
	ID          int64
	ObjectName  string
	WrappedDEK  []byte
	Nonce       []byte
	OrigName    string
	ContentType string
	Size        int64
	CreatedAt   string // fixed name here
}

type DB struct{ *sql.DB }

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS files(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		object_name TEXT UNIQUE,
		wrapped_dek BLOB,
		nonce BLOB,
		orig_name TEXT,
		content_type TEXT,
		size INTEGER,
		created_at TEXT DEFAULT (datetime('now'))
	);`)
	if err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (d *DB) Insert(f FileMeta) error {
	_, err := d.Exec(`INSERT INTO files(object_name,wrapped_dek,nonce,orig_name,content_type,size)
	VALUES(?,?,?,?,?,?)`, f.ObjectName, f.WrappedDEK, f.Nonce, f.OrigName, f.ContentType, f.Size)
	return err
}

func (d *DB) Get(object string) (*FileMeta, error) {
	row := d.QueryRow(`SELECT id,object_name,wrapped_dek,nonce,orig_name,content_type,size,created_at
	 FROM files WHERE object_name=?`, object)
	var f FileMeta
	if err := row.Scan(&f.ID, &f.ObjectName, &f.WrappedDEK, &f.Nonce, &f.OrigName, &f.ContentType, &f.Size, &f.CreatedAt); err != nil {
		return nil, err
	}
	return &f, nil
}

func (d *DB) List() ([]FileMeta, error) {
	rows, err := d.Query(`SELECT id,object_name,orig_name,size,created_at FROM files ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileMeta
	for rows.Next() {
		var f FileMeta
		if err := rows.Scan(&f.ID, &f.ObjectName, &f.OrigName, &f.Size, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
