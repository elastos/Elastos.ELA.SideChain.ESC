package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/syndtr/goleveldb/leveldb"
	dbutil "github.com/syndtr/goleveldb/leveldb/util"
)

// Ensure arbiters implement arbiters interface.
var _ Arbiters = (*arbiters)(nil)

type RevertInfo struct {
	WorkingHeight uint32
	Mode          byte
}

type arbiters struct {
	batch
	sync.RWMutex
	db             *leveldb.DB
	b              *leveldb.Batch
	posCache       []uint32
	revertPOSCache []RevertInfo
	cache          map[common.Uint256]uint32
	originArbiters [][]byte
	arbitersCount  int
}

func NewArbiters(db *leveldb.DB, originArbiters [][]byte, arbitersCount int) *arbiters {
	return &arbiters{
		db:             db,
		b:              new(leveldb.Batch),
		posCache:       make([]uint32, 0),
		cache:          make(map[common.Uint256]uint32),
		originArbiters: originArbiters,
		arbitersCount:  arbitersCount,
	}
}

func (c *arbiters) Put(height uint32, crcArbiters [][]byte, normalArbiters [][]byte) error {
	c.Lock()
	defer c.Unlock()
	if err := c.batchPut(height, crcArbiters, normalArbiters, c.b); err != nil {
		return err
	}
	c.db.Write(c.b, nil)
	return nil
}

func (c *arbiters) batchPut(height uint32, crcArbiters [][]byte, normalArbiters [][]byte, batch *leveldb.Batch) error {
	batch.Put(BKTArbPosition, uint32toBytes(height))

	// update positions
	posCache := c.getCurrentPositions()
	newPosCache := make([]uint32, 0)
	for _, p := range posCache {
		if p < height {
			newPosCache = append(newPosCache, p)
		}
	}
	newPosCache = append(newPosCache, height)
	c.posCache = newPosCache
	batch.Put(BKTArbPositions, uint32ArrayToBytes(c.posCache))

	data := getValueBytes(crcArbiters, normalArbiters)
	hash := calcHash(data)
	key, err := common.Uint256FromBytes(hash[:])
	if err != nil {
		return err
	}
	val, ok := c.cache[*key]
	index := getIndex(height)
	if !ok {
		existHeight, err := c.db.Get(toKey(BKTTransactionHeight, hash[:]...), nil)
		if err == nil {
			c.cache[*key] = bytesToUint32(existHeight)
			batch.Put(toKey(BKTArbitersData, index...), existHeight)
			return nil
		} else if err == leveldb.ErrNotFound {
			c.cache[*key] = height
			batch.Put(toKey(BKTArbitersData, index...), data)
			batch.Put(toKey(BKTTransactionHeight, hash[:]...), uint32toBytes(height))
			return nil
		} else {
			return err
		}
	}

	batch.Put(toKey(BKTArbitersData, index...), uint32toBytes(val))
	return nil
}

func (c *arbiters) BatchPut(height uint32, crcArbiters [][]byte, normalArbiters [][]byte, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()
	return c.batchPut(height, crcArbiters, normalArbiters, batch)
}

func (c *arbiters) Get() (crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	c.RLock()
	defer c.RUnlock()
	return c.GetByHeight(c.getCurrentPosition())
}

func (c *arbiters) GetNext() (workingHeight uint32, crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	c.RLock()
	defer c.RUnlock()
	workingHeight = c.getCurrentPosition()
	crcArbiters, normalArbiters, err = c.get(workingHeight)
	return
}

func (c *arbiters) get(height uint32) (crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	var val []byte
	val, err = c.db.Get(toKey(BKTArbitersData, getIndex(height)...), nil)
	if err != nil {
		return
	}
	if len(val) == 4 {
		val, err = c.db.Get(toKey(BKTArbitersData, getIndex(bytesToUint32(val))...), nil)
		if err != nil {
			return
		}
	}
	r := bytes.NewReader(val)
	crcCount, err := common.ReadUint8(r)
	if err != nil {
		return
	}
	for i := uint8(0); i < crcCount; i++ {
		cr, err := common.ReadVarBytes(r, 33, "public key")
		if err != nil {
			return nil, nil, err
		}
		crcArbiters = append(crcArbiters, cr)
	}
	normalCount, err := common.ReadUint8(r)
	if err != nil {
		return
	}
	for i := uint8(0); i < normalCount; i++ {
		producer, err := common.ReadVarBytes(r, 33, "public key")
		if err != nil {
			return nil, nil, err
		}
		normalArbiters = append(normalArbiters, producer)
	}
	return
}

func (c *arbiters) GetByHeight(height uint32) (crcArbiters [][]byte, normalArbiters [][]byte, err error) {
	c.RLock()
	defer c.RUnlock()
	var pos []uint32
	if len(c.posCache) == 0 {
		pos = c.getCurrentPositions()
		c.posCache = pos
	} else {
		pos = c.posCache
	}
	slot, err := findSlot(pos, height, c.arbitersCount)
	if err != nil {
		return nil, nil, err
	}
	if slot == 0 {
		return c.originArbiters, nil, nil
	}
	height = slot
	return c.get(height)
}

func (c *arbiters) Close() error {
	c.Lock()
	return nil
}

func (c *arbiters) Clear() error {
	c.Lock()
	defer c.Unlock()
	it := c.db.NewIterator(dbutil.BytesPrefix(BKTArbiters), nil)
	defer it.Release()
	for it.Next() {
		c.b.Delete(it.Key())
	}
	c.b.Delete(BKTArbPosition)
	return c.db.Write(c.b, nil)
}

func (c *arbiters) getCurrentPosition() uint32 {
	pos, err := c.db.Get(BKTArbPosition, nil)
	if err == nil {
		return bytesToUint32(pos)
	}

	return 0
}

func (c *arbiters) getCurrentPositions() []uint32 {
	pos, err := c.db.Get(BKTArbPositions, nil)
	if err == nil {
		return bytesToUint32Array(pos)
	}
	return nil
}

func (c *arbiters) getCurrentRevertPosition() uint32 {
	pos, err := c.db.Get(BKTRevertPosition, nil)
	if err == nil {
		return bytesToUint32(pos)
	}

	return 0
}

func (c *arbiters) getCurrentRevertPositions() ([]RevertInfo, error) {
	pos, err := c.db.Get(BKTRevertPositions, nil)
	if err != nil {
		return nil, err
	}
	return bytesToRevertInfoArray(pos)
}

func (c *arbiters) Commit() error {
	return c.db.Write(c.b, nil)
}

func (c *arbiters) Rollback() error {
	c.b.Reset()
	return nil
}

func (c *arbiters) CommitBatch(batch *leveldb.Batch) error {
	return c.db.Write(batch, nil)
}

func (c *arbiters) RollbackBatch(batch *leveldb.Batch) error {
	batch.Reset()
	return nil
}

func uint32toBytes(data uint32) []byte {
	var r [4]byte
	binary.LittleEndian.PutUint32(r[:], data)
	return r[:]
}

func uint32ArrayToBytes(data []uint32) []byte {
	var r [4]byte
	binary.LittleEndian.PutUint32(r[:], uint32(len(data)))
	var buffer bytes.Buffer
	buffer.Write(r[:])
	for i := 0; i < len(data); i++ {
		buffer.Write(uint32toBytes(data[i]))
	}
	return buffer.Bytes()
}

func revertInfoArrayToBytes(data []RevertInfo) ([]byte, error) {
	w := new(bytes.Buffer)
	if err := common.WriteVarUint(w, uint64(len(data))); err != nil {
		return nil, err
	}
	for _, r := range data {
		if err := common.WriteUint32(w, r.WorkingHeight); err != nil {
			return nil, err
		}
		if err := w.WriteByte(r.Mode); err != nil {
			return nil, err
		}

	}
	return w.Bytes(), nil
}

func bytesToRevertInfoArray(data []byte) ([]RevertInfo, error) {
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	results := make([]RevertInfo, 0)
	for i := uint64(0); i < count; i++ {
		workingHeight, err := common.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		mode, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		results = append(results, RevertInfo{
			WorkingHeight: workingHeight,
			Mode:          mode,
		})
	}
	return results, nil
}

func getIndex(data uint32) []byte {
	var kdata [4]byte
	binary.LittleEndian.PutUint32(kdata[:], data)
	return toKey(BKTArbiters, kdata[:]...)
}

func bytesToUint32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

func bytesToUint32Array(data []byte) []uint32 {
	len := binary.LittleEndian.Uint32(data)
	var ret []uint32
	for i := 0; i < int(len); i++ {
		val := data[(i*4)+4 : (i+1)*4+4]
		ret = append(ret, binary.LittleEndian.Uint32(val))
	}
	return ret
}

func getValueBytes(crc [][]byte, nor [][]byte) []byte {
	buf := new(bytes.Buffer)
	sort.Slice(crc, func(i, j int) bool {
		return bytes.Compare(crc[i], crc[j]) < 0
	})
	common.WriteUint8(buf, uint8(len(crc)))
	for _, v := range crc {
		common.WriteVarBytes(buf, v)
	}
	sort.Slice(nor, func(i, j int) bool {
		return bytes.Compare(nor[i], nor[j]) < 0
	})
	common.WriteUint8(buf, uint8(len(nor)))
	for _, v := range nor {
		common.WriteVarBytes(buf, v)
	}

	return buf.Bytes()
}

func findSlot(pos []uint32, height uint32, arbitersCount int) (uint32, error) {

	if len(pos) == 0 {
		return 0, errors.New("invalid height")
	}

	if pos[len(pos)-1]+uint32(arbitersCount) < height {
		return 0, errors.New("invalid height")
	}

	for i := len(pos) - 1; i >= 0; i-- {
		if height > pos[i] {
			return pos[i], nil
		}
	}

	return 0, nil
}

func calcHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func (c *arbiters) GetRevertInfo() []RevertInfo {
	c.RLock()
	defer c.RUnlock()
	var pos []RevertInfo
	if len(c.revertPOSCache) == 0 {
		var err error
		pos, err = c.getCurrentRevertPositions()
		if err!= nil && err != leveldb.ErrNotFound {
			return pos
		}
		c.revertPOSCache = pos
	} else {
		pos = c.revertPOSCache
	}

	return pos
}

func (c *arbiters) GetConsensusAlgorithmByHeight(height uint32) (byte, error) {
	c.RLock()
	defer c.RUnlock()
	var pos []RevertInfo
	if len(c.revertPOSCache) == 0 {
		var err error
		pos, err = c.getCurrentRevertPositions()
		if err!= nil && err != leveldb.ErrNotFound {
			return 0, err
		}
		c.revertPOSCache = pos
	} else {
		pos = c.revertPOSCache
	}

	var revertInfo RevertInfo
	for _, p := range pos {
		if p.WorkingHeight > height {
			break
		}
		revertInfo = p
	}

	return revertInfo.Mode, nil
}

func (c *arbiters) BatchPutRevertTransaction(batch *leveldb.Batch, workingHeight uint32, mode byte) error {
	c.Lock()
	defer c.Unlock()

	pos := c.getCurrentRevertPosition()
	var isRollback bool
	if workingHeight <= pos {
		isRollback = true
	}
	batch.Put(BKTRevertPosition, uint32toBytes(workingHeight))
	if !isRollback {
		posCache, err := c.getCurrentRevertPositions()
		if err != nil && err != leveldb.ErrNotFound {
			return err
		}
		newPosCache := make([]RevertInfo, 0)
		for _, p := range posCache {
			if p.WorkingHeight < workingHeight {
				newPosCache = append(newPosCache, p)
			}
		}
		newPosCache = append(newPosCache, RevertInfo{
			WorkingHeight: workingHeight,
			Mode:          mode,
		})
		c.revertPOSCache = newPosCache
		data, err := revertInfoArrayToBytes(c.revertPOSCache)
		if err != nil {
			return err
		}
		batch.Put(BKTRevertPositions, data)
	}

	return nil
}
