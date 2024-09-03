package spv

import (
	"bytes"
	"encoding/binary"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// used to compute the size of bloom filter bits array .
// too small will lead to high false positive rate.
const BITSPERKEY = 10

// prefix of blocks in level db
var BlockPrefix = []byte("merkle_block")

type BlockRecorder struct {
	ldb *leveldb.DB
}

func (b *BlockRecorder) SaveBlock(block *util.Block) error {

	var key bytes.Buffer
	key.Write(BlockPrefix)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], block.Height)
	key.Write(buf[:])

	data, err := block.Serialize()
	if err != nil {
		return err
	}

	return b.ldb.Put(key.Bytes(), data, nil)
}

func (b *BlockRecorder) GetBlockByHeight(height uint32) (*util.Block, error) {
	var key bytes.Buffer
	key.Write(BlockPrefix)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], height)
	key.Write(buf[:])

	data, err := b.ldb.Get(key.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	block := util.Block{}
	if err = block.Deserialize(data); err != nil {
		return nil, err
	}

	return &block, nil
}

func NewBlockRecorder(filePath string) (*BlockRecorder, error) {
	ldb, err := newLevelDB(filePath)
	if err != nil {
		return nil, err
	}
	return &BlockRecorder{ldb: ldb}, nil
}

func newLevelDB(file string) (*leveldb.DB, error) {
	// default Options
	o := opt.Options{
		NoSync: false,
		Filter: filter.NewBloomFilter(BITSPERKEY),
	}

	db, err := leveldb.OpenFile(file, &o)
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil)
	}

	if err != nil {
		return nil, err
	}

	return db, nil
}
