package store

import (
	"bytes"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Ensure customID implement CustomID interface.
var _ CustomID = (*customID)(nil)

var BKTReservedCustomID = []byte("RS")
var BKTReceivedCustomID = []byte("RC")
var BKTChangeCustomIDFee = []byte("CF")
var BKTLastCustomIDFee = []byte("CH")

const DefaultFeeRate common.Fixed64 = 1e8

type customID struct {
	batch
	sync.RWMutex
	db                *leveldb.DB
	b                 *leveldb.Batch
	cache             map[common.Uint256]uint32
	reservedCustomIDs map[string]struct{}
	receivedCustomIDs map[string]common.Uint168
	feeRate           common.Fixed64
}

func NewCustomID(db *leveldb.DB) *customID {
	return &customID{
		db:                db,
		b:                 new(leveldb.Batch),
		cache:             make(map[common.Uint256]uint32),
		reservedCustomIDs: make(map[string]struct{}, 0),
		receivedCustomIDs: make(map[string]common.Uint168, 0),
		feeRate:           common.Fixed64(0),
	}
}

func (c *customID) PutControversialReservedCustomIDs(
	reservedCustomIDs []string, proposalHash common.Uint256) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutControversialReservedCustomIDs(
		reservedCustomIDs, proposalHash, batch); err != nil {
		return err
	}
	return c.db.Write(batch, nil)
}

func (c *customID) PutControversialReceivedCustomIDs(receivedCustomIDs []string,
	did common.Uint168, proposalHash common.Uint256) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutControversialReceivedCustomIDs(
		receivedCustomIDs, did, proposalHash, batch); err != nil {
		return err
	}
	return c.db.Write(batch, nil)
}

func (c *customID) PutControversialChangeCustomIDFee(rate common.Fixed64, proposalHash common.Uint256) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutControversialChangeCustomIDFee(rate, proposalHash, batch); err != nil {
		return err
	}
	return c.db.Write(batch, nil)
}

func (c *customID) PutCustomIDProposalResults(
	results []payload.ProposalResult) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutCustomIDProposalResults(results, batch); err != nil {
		return err
	}
	return c.db.Write(batch, nil)
}

func (c *customID) BatchPutControversialReservedCustomIDs(
	reservedCustomIDs []string, proposalHash common.Uint256, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutControversialReservedCustomIDs(reservedCustomIDs, proposalHash, batch)
}

func (c *customID) BatchDeleteControversialReservedCustomIDs(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	c.Lock()
	defer c.Unlock()
	batch.Delete(toKey(BKTReservedCustomID, proposalHash.Bytes()...))
}

func (c *customID) BatchPutControversialReceivedCustomIDs(receivedCustomIDs []string,
	did common.Uint168, proposalHash common.Uint256, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutControversialReceivedCustomIDs(receivedCustomIDs, did, proposalHash, batch)
}

func (c *customID) BatchDeleteControversialReceivedCustomIDs(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	c.Lock()
	defer c.Unlock()

	batch.Delete(toKey(BKTReceivedCustomID, proposalHash.Bytes()...))
}

func (c *customID) BatchPutControversialChangeCustomIDFee(rate common.Fixed64,
	proposalHash common.Uint256, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutControversialChangeCustomIDFee(rate, proposalHash, batch)
}

func (c *customID) BatchDeleteControversialChangeCustomIDFee(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	c.Lock()
	defer c.Unlock()

	batch.Delete(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...))
}

func (c *customID) BatchPutCustomIDProposalResults(
	results []payload.ProposalResult, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutCustomIDProposalResults(results, batch)
}

func (c *customID) batchPutCustomIDProposalResults(
	results []payload.ProposalResult, batch *leveldb.Batch) error {
	// add new reserved custom ID into cache.
	for _, r := range results {
		switch r.ProposalType {
		case payload.ReserveCustomID:
			// initialize cache.
			if len(c.reservedCustomIDs) == 0 {
				existedCustomIDs, err := c.getReservedCustomIDsFromDB()
				if err != nil {
					return err
				}else{
					c.reservedCustomIDs = existedCustomIDs
				}
			}
			if r.Result == true {
				// update cache.
				reservedCustomIDs, err := c.getControversialReservedCustomIDsFromDB(r.ProposalHash)
				if err != nil {
					return err
				}
				for k, v := range reservedCustomIDs {
					c.reservedCustomIDs[k] = v
				}
				// update db.
				if err := c.batchPutReservedCustomIDs(batch); err != nil {
					return err
				}
			} else {
				// if you need to remove data from db, you need to consider rollback.
				//c.removeControversialReservedCustomIDsFromDB(r.ProposalHash, batch)
			}

		case payload.ReceiveCustomID:
			// initialize cache.
			if len(c.receivedCustomIDs) == 0 {
				existedCustomIDs, err := c.getReceivedCustomIDsFromDB()
				if err != nil {
					return err
				}else{
					c.receivedCustomIDs = existedCustomIDs
				}
			}
			if r.Result == true {
				// update cache.
				receivedCustomIDs, err := c.getControversialReceivedCustomIDsFromDB(r.ProposalHash)
				if err != nil {
					return err
				}
				for k, v := range receivedCustomIDs {
					c.receivedCustomIDs[k] = v
				}
				// update db.
				if err := c.batchPutReceivedCustomIDs(batch); err != nil {
					return err
				}
			} else {
				// if you need to remove data from db, you need to consider rollback.
				//c.removeControversialReceivedCustomIDsFromDB(r.ProposalHash, batch)
			}

		case payload.ChangeCustomIDFee:
			// initialize cache.
			if c.feeRate == 0 {
				feeRate, _ := c.getCustomIDFeeRateFromDB()
				// todo consider other errors
				if feeRate == 0 {
					feeRate = DefaultFeeRate
				}
				c.feeRate = feeRate
			}

			if r.Result == true {
				rate, err := c.getControversialCustomIDFeeRate(r.ProposalHash)
				if err != nil {
					return err
				}

				// update db.
				if err := c.batchPutLastCustomIDFee(batch, r.ProposalHash); err != nil {
					return err
				}
				c.feeRate = rate
				if err := c.batchPutChangeCustomIDFee(batch); err != nil {
					return err
				}
			} else {
				// if you need to remove data from db, you need to consider rollback.
				//c.removeControversialCustomIDFeeRate(r.ProposalHash, batch)
			}
		}
	}
	return nil
}

func (c *customID) batchPutControversialReservedCustomIDs(
	reservedCustomIDs []string, proposalHash common.Uint256, batch *leveldb.Batch) error {
	// store reserved custom ID.
	w := new(bytes.Buffer)
	err := common.WriteVarUint(w, uint64(len(reservedCustomIDs)))
	if err != nil {
		return err
	}
	for _, v := range reservedCustomIDs {
		if err := common.WriteVarString(w, v); err != nil {
			return err
		}
	}
	batch.Put(toKey(BKTReservedCustomID, proposalHash.Bytes()...), w.Bytes())
	return nil
}

func (c *customID) batchPutReservedCustomIDs(batch *leveldb.Batch) error {
	// store reserved custom ID.

	w := new(bytes.Buffer)
	err := common.WriteVarUint(w, uint64(len(c.reservedCustomIDs)))
	if err != nil {
		return err
	}
	for k, _ := range c.reservedCustomIDs {
		if err := common.WriteVarString(w, k); err != nil {
			return err
		}
	}
	batch.Put(BKTReservedCustomID, w.Bytes())
	return nil
}

func (c *customID) batchPutControversialReceivedCustomIDs(
	receivedCustomIDs []string, did common.Uint168,
	proposalHash common.Uint256, batch *leveldb.Batch) error {
	w := new(bytes.Buffer)
	err := common.WriteUint32(w, uint32(len(receivedCustomIDs)))
	if err != nil {
		return err
	}
	for _, id := range receivedCustomIDs {
		if err := common.WriteVarString(w, id); err != nil {
			return err
		}
		if err := did.Serialize(w); err != nil {
			return err
		}
	}
	batch.Put(toKey(BKTReceivedCustomID, proposalHash.Bytes()...), w.Bytes())
	return nil
}

func (c *customID) batchPutReceivedCustomIDs(batch *leveldb.Batch) error {
	w := new(bytes.Buffer)
	err := common.WriteUint32(w, uint32(len(c.receivedCustomIDs)))
	if err != nil {
		return err
	}
	for id, did := range c.receivedCustomIDs {
		if err := common.WriteVarString(w, id); err != nil {
			return err
		}
		if err := did.Serialize(w); err != nil {
			return err
		}
	}
	batch.Put(BKTReceivedCustomID, w.Bytes())
	return nil
}

func (c *customID) batchPutControversialChangeCustomIDFee(rate common.Fixed64,
	proposalHash common.Uint256, batch *leveldb.Batch) error {
	w := new(bytes.Buffer)
	if err := rate.Serialize(w); err != nil {
		return err
	}
	batch.Put(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...), w.Bytes())
	return nil
}

func (c *customID) batchPutChangeCustomIDFee(batch *leveldb.Batch) error {
	w := new(bytes.Buffer)
	if err := c.feeRate.Serialize(w); err != nil {
		return err
	}
	batch.Put(BKTChangeCustomIDFee, w.Bytes())
	return nil

}

func (c *customID) batchPutLastCustomIDFee(batch *leveldb.Batch,
	proposalHash common.Uint256) error {
	w := new(bytes.Buffer)
	if err := c.feeRate.Serialize(w); err != nil {
		return err
	}
	batch.Put(toKey(BKTLastCustomIDFee, proposalHash.Bytes()...), w.Bytes())
	return nil
}

func (c *customID) gutLastCustomIDFee(proposalHash common.Uint256) (common.Fixed64, error) {
	key := toKey(BKTLastCustomIDFee, proposalHash.Bytes()...)
	var val []byte
	val, err := c.db.Get(key, nil)
	if err != nil {
		return 0, err
	}
	r := bytes.NewReader(val)
	var feeRate common.Fixed64
	err = feeRate.Deserialize(r)
	if err != nil {
		return 0, err
	}

	return feeRate, nil
}

func (c *customID) GetReservedCustomIDs() (map[string]struct{}, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getReservedCustomIDs()
}

func (c *customID) GetReceivedCustomIDs() (map[string]common.Uint168, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getReceivedCustomIDs()
}

func (c *customID) GetCustomIDFeeRate() (common.Fixed64, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getCustomIDFeeRate()
}

func (c *customID) getReservedCustomIDs() (map[string]struct{}, error) {
	if len(c.reservedCustomIDs) != 0 {
		return c.reservedCustomIDs, nil
	}

	ids, err := c.getReservedCustomIDsFromDB()
	if err != nil {
		return nil, err
	}
	// refresh the cache.
	c.reservedCustomIDs = ids
	return ids, nil
}

func (c *customID) getControversialReservedCustomIDsFromDB(proposalHash common.Uint256) (map[string]struct{}, error) {
	var val []byte
	val, err := c.db.Get(toKey(BKTReservedCustomID, proposalHash.Bytes()...), nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadVarUint(r,0)
	if err != nil {
		return nil, err
	}
	reservedCustomIDs := make(map[string]struct{}, 0)
	for i := uint64(0); i < count; i++ {
		id, err := common.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		reservedCustomIDs[id] = struct{}{}
	}
	return reservedCustomIDs, nil
}

func (c *customID) removeControversialReservedCustomIDsFromDB(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	batch.Delete(toKey(BKTReservedCustomID, proposalHash.Bytes()...))
}

func (c *customID) getReservedCustomIDsFromDB() (map[string]struct{}, error) {
	reservedCustomIDs := make(map[string]struct{}, 0)

	var val []byte
	val, err := c.db.Get(BKTReservedCustomID, nil)
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			return reservedCustomIDs, nil
		}
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < count; i++ {
		id, err := common.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		reservedCustomIDs[id] = struct{}{}
	}
	return reservedCustomIDs, nil
}

func (c *customID) getControversialReceivedCustomIDsFromDB(
	proposalHash common.Uint256) (map[string]common.Uint168, error) {
	var val []byte
	val, err := c.db.Get(toKey(BKTReceivedCustomID, proposalHash.Bytes()...), nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	receiedCustomIDs := make(map[string]common.Uint168, 0)
	for i := uint32(0); i < count; i++ {
		id, err := common.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		var did common.Uint168
		if err = did.Deserialize(r); err != nil {
			return nil, err
		}
		receiedCustomIDs[id] = did
	}
	return receiedCustomIDs, nil
}

func (c *customID) removeControversialReceivedCustomIDsFromDB(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	batch.Delete(toKey(BKTReceivedCustomID, proposalHash.Bytes()...))
}

func (c *customID) getReceivedCustomIDsFromDB() (map[string]common.Uint168, error) {
	receiedCustomIDs := make(map[string]common.Uint168, 0)

	var val []byte
	val, err := c.db.Get(BKTReceivedCustomID, nil)
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			return receiedCustomIDs, nil
		}
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadUint32(r)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < count; i++ {
		id, err := common.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		var did common.Uint168
		if err = did.Deserialize(r); err != nil {
			return nil, err
		}
		receiedCustomIDs[id] = did
	}
	return receiedCustomIDs, nil
}

func (c *customID) getReceivedCustomIDs() (map[string]common.Uint168, error) {
	if len(c.receivedCustomIDs) != 0 {
		return c.receivedCustomIDs, nil
	}

	ids, err := c.getReceivedCustomIDsFromDB()
	if err != nil {
		return nil, err
	}
	// refresh the cache.
	c.receivedCustomIDs = ids
	return ids, nil
}

func (c *customID) getCustomIDFeeRate() (common.Fixed64, error) {
	if c.feeRate != 0 {
		return c.feeRate, nil
	}
	feeRate, _ := c.getCustomIDFeeRateFromDB()
	//// todo consider other errors
	c.feeRate = feeRate
	return feeRate, nil
}

func (c *customID) getCustomIDFeeRateFromDB() (common.Fixed64, error) {
	var val []byte
	val, err := c.db.Get(BKTChangeCustomIDFee, nil)
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			return 0,nil
		}
		return 0, err
	}
	r := bytes.NewReader(val)
	var rate common.Fixed64
	if err := rate.Deserialize(r); err != nil {
		return 0, err
	}
	return rate, nil
}

func (c *customID) getControversialCustomIDFeeRate(proposalHash common.Uint256) (common.Fixed64, error) {
	var val []byte
	val, err := c.db.Get(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...), nil)
	if err != nil {
		return 0, err
	}
	r := bytes.NewReader(val)
	var rate common.Fixed64
	if err := rate.Deserialize(r); err != nil {
		return 0, err
	}
	return rate, nil
}

func (c *customID) removeControversialCustomIDFeeRate(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	batch.Delete(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...))
}

func (c *customID) Close() error {
	c.Lock()
	return nil
}

func (c *customID) Clear() error {
	c.Lock()
	defer c.Unlock()

	batch := new(leveldb.Batch)
	it := c.db.NewIterator(util.BytesPrefix(BKTReservedCustomID), nil)
	defer it.Release()
	for it.Next() {
		batch.Delete(it.Key())
	}

	it = c.db.NewIterator(util.BytesPrefix(BKTReceivedCustomID), nil)
	defer it.Release()
	for it.Next() {
		batch.Delete(it.Key())
	}

	it = c.db.NewIterator(util.BytesPrefix(BKTChangeCustomIDFee), nil)
	defer it.Release()
	for it.Next() {
		batch.Delete(it.Key())
	}
	return c.db.Write(c.b, nil)
}

func (c *customID) Commit() error {
	return c.db.Write(c.b, nil)
}

func (c *customID) Rollback() error {
	c.b.Reset()
	return nil
}

func (c *customID) CommitBatch(batch *leveldb.Batch) error {
	return c.db.Write(batch, nil)
}

func (c *customID) RollbackBatch(batch *leveldb.Batch) error {
	batch.Reset()
	return nil
}
