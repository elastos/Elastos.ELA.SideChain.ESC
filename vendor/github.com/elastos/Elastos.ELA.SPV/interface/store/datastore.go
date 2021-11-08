package store

import (
	"path/filepath"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
)

// Ensure dataStore implement DataStore interface.
var _ DataStore = (*dataStore)(nil)

type dataStore struct {
	sync.RWMutex
	db    *leveldb.DB
	addrs *addrs
	txs   *txs
	ops   *ops
	que   *que
	ars   *arbiters
	cid   *customID
}

////this spv GenesisBlockAddress
//	GenesisBlockAddress    string
func NewDataStore(dataDir string, originArbiters [][]byte, arbitersCount int, GenesisBlockAddress    string) (*dataStore, error) {
	db, err := leveldb.OpenFile(filepath.Join(dataDir, "store"), nil)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	addrs, err := NewAddrs(db)
	if err != nil {
		return nil, err
	}

	return &dataStore{
		db:    db,
		addrs: addrs,
		txs:   NewTxs(db),
		ops:   NewOps(db),
		que:   NewQue(db),
		ars:   NewArbiters(db, originArbiters, arbitersCount),
		cid:   NewCustomID(db, GenesisBlockAddress),
	}, nil
}

func (d *dataStore) Addrs() Addrs {
	return d.addrs
}

func (d *dataStore) Txs() Txs {
	return d.txs
}

func (d *dataStore) Ops() Ops {
	return d.ops
}

func (d *dataStore) Que() Que {
	return d.que
}

func (d *dataStore) Arbiters() Arbiters {
	return d.ars
}

func (d *dataStore) CID() CustomID {
	return d.cid
}

func (d *dataStore) Batch() DataBatch {
	return &dataBatch{
		DB:       d.db,
		customID: d.cid,
		Batch:    new(leveldb.Batch),
	}
}

func (d *dataStore) Clear() error {
	d.Lock()
	defer d.Unlock()

	d.que.Clear()

	it := d.db.NewIterator(nil, nil)
	batch := new(leveldb.Batch)
	for it.Next() {
		batch.Delete(it.Key())
	}
	it.Release()

	return d.db.Write(batch, nil)
}

// Close db
func (d *dataStore) Close() error {
	d.Lock()
	defer d.Unlock()

	d.addrs.Close()
	d.txs.Close()
	d.ops.Close()
	d.que.Close()
	d.ars.Close()
	d.cid.Close()
	return d.db.Close()
}
