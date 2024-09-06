package spv

import (
	"bytes"
	"encoding/binary"

	"github.com/elastos/Elastos.ELA.SPV/interface/iutil"
	"github.com/elastos/Elastos.ELA.SPV/util"
	elacommon "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// used to compute the size of bloom filter bits array .
// too small will lead to high false positive rate.
const BITSPERKEY = 10

// prefix of blocks in level db
var BlockHeaderPrefix = []byte("merkle_block_header")

type BlockRecorder struct {
	ldb *leveldb.DB
}

func (b *BlockRecorder) SaveBlockHeader(blockHeader *util.Header) error {
	var key bytes.Buffer
	key.Write(BlockHeaderPrefix)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], blockHeader.Height)
	key.Write(buf[:])

	data, err := blockHeader.Serialize()
	if err != nil {
		return err
	}
	return b.ldb.Put(key.Bytes(), data, nil)
}

func newBlockHeader() util.BlockHeader {
	return iutil.NewHeader(&elacommon.Header{})
}

func (b *BlockRecorder) GetBlockHeaderByHeight(height uint32) (*util.Header, error) {
	var key bytes.Buffer
	key.Write(BlockHeaderPrefix)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], height)
	key.Write(buf[:])

	data, err := b.ldb.Get(key.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	var header util.Header
	header.BlockHeader = newBlockHeader()
	if err = header.Deserialize(data); err != nil {
		return nil, err
	}

	return &header, nil
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
