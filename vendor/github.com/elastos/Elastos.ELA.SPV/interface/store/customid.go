package store

import (
	"bytes"
	"errors"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Ensure customID implement CustomID interface.
var _ CustomID = (*customID)(nil)

const (
	DefaultConfirmations uint32         = 6
	DefaultFeeRate       common.Fixed64 = 1e8
)

type CustomIDInfo struct {
	DID    common.Uint168
	Height uint32
}

type customID struct {
	batch
	sync.RWMutex
	db                  *leveldb.DB
	b                   *leveldb.Batch
	cache               map[common.Uint256]uint32
	reservedCustomIDs   map[string]uint32
	receivedCustomIDs   map[string]CustomIDInfo // key: customID
	customIDFeePosCache []uint32

	//this spv GenesisBlockAddress
	GenesisBlockAddress string
}

func NewCustomID(db *leveldb.DB, GenesisBlockAddress string) *customID {
	return &customID{
		db:                  db,
		b:                   new(leveldb.Batch),
		cache:               make(map[common.Uint256]uint32),
		reservedCustomIDs:   make(map[string]uint32, 0),
		receivedCustomIDs:   make(map[string]CustomIDInfo, 0),
		GenesisBlockAddress: GenesisBlockAddress,
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

func (c *customID) PutControversialChangeCustomIDFee(rate common.Fixed64, proposalHash common.Uint256, workingHeight uint32) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutControversialChangeCustomIDFee(rate, workingHeight, proposalHash, batch); err != nil {
		return err
	}
	return c.db.Write(batch, nil)
}

func (c *customID) PutCustomIDProposalResults(
	results []payload.ProposalResult, height uint32) error {
	c.Lock()
	defer c.Unlock()
	batch := new(leveldb.Batch)
	if err := c.batchPutCustomIDProposalResults(results, height, batch); err != nil {
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
	proposalHash common.Uint256, workingHeight uint32, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutControversialChangeCustomIDFee(rate, workingHeight, proposalHash, batch)
}

func (c *customID) BatchDeleteControversialChangeCustomIDFee(
	proposalHash common.Uint256, batch *leveldb.Batch) {
	c.Lock()
	defer c.Unlock()

	batch.Delete(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...))
}

func (c *customID) BatchPutCustomIDProposalResults(
	results []payload.ProposalResult, height uint32, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()

	return c.batchPutCustomIDProposalResults(results, height, batch)
}

func (c *customID) batchPutCustomIDProposalResults(
	results []payload.ProposalResult, height uint32, batch *leveldb.Batch) error {
	// add new reserved custom ID into cache.
	for _, r := range results {
		switch r.ProposalType {
		case payload.ReserveCustomID:
			// initialize cache.
			if len(c.reservedCustomIDs) == 0 {
				existedCustomIDs, err := c.getReservedCustomIDsFromDB()
				if err != nil {
					return err
				} else {
					c.reservedCustomIDs = existedCustomIDs
				}
			}
			if r.Result == true {
				// update cache.
				reservedCustomIDs, err := c.getControversialReservedCustomIDsFromDB(r.ProposalHash)
				if err != nil {
					return err
				}
				for k, _ := range reservedCustomIDs {
					c.reservedCustomIDs[k] = height
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
				} else {
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
					c.receivedCustomIDs[k] = CustomIDInfo{
						DID:    v,
						Height: height,
					}
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
			if r.Result == true {
				rate, workingHeight, err := c.getControversialCustomIDFeeRateByProposalHash(r.ProposalHash)
				if err != nil {
					return err
				}
				if err := c.batchPutChangeCustomIDFee(batch, rate, workingHeight); err != nil {
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
	for k, v := range c.reservedCustomIDs {
		if err := common.WriteVarString(w, k); err != nil {
			return err
		}
		if err := common.WriteUint32(w, v); err != nil {
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
	for id, info := range c.receivedCustomIDs {
		if err := common.WriteVarString(w, id); err != nil {
			return err
		}
		if err := info.DID.Serialize(w); err != nil {
			return err
		}
		if err := common.WriteUint32(w, info.Height); err != nil {
			return err
		}
	}
	batch.Put(BKTReceivedCustomID, w.Bytes())
	return nil
}

func (c *customID) batchPutControversialChangeCustomIDFee(rate common.Fixed64,
	workingHeight uint32, proposalHash common.Uint256, batch *leveldb.Batch) error {
	w := new(bytes.Buffer)
	if err := rate.Serialize(w); err != nil {
		return err
	}
	if err := common.WriteUint32(w, workingHeight); err != nil {
		return err
	}
	batch.Put(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...), w.Bytes())
	return nil
}

func (c *customID) getCurrentCustomIDFeePositions() []uint32 {
	pos, err := c.db.Get(BKTCustomIDFeePositions, nil)
	if err == nil {
		return bytesToUint32Array(pos)
	}
	return nil
}

func (c *customID) batchPutChangeCustomIDFee(batch *leveldb.Batch, feeRate common.Fixed64, workingHeight uint32) error {
	posCache := c.getCurrentCustomIDFeePositions()
	newPosCache := make([]uint32, 0)
	for _, p := range posCache {
		if p < workingHeight {
			newPosCache = append(newPosCache, p)
		}
	}
	newPosCache = append(newPosCache, workingHeight)
	c.customIDFeePosCache = newPosCache
	batch.Put(BKTCustomIDFeePositions, uint32ArrayToBytes(c.customIDFeePosCache))

	buf := new(bytes.Buffer)
	if err := common.WriteUint32(buf, workingHeight); err != nil {
		return err
	}
	key := toKey(BKTChangeCustomIDFee, buf.Bytes()...)
	w := new(bytes.Buffer)
	if err := feeRate.Serialize(w); err != nil {
		return err
	}
	batch.Put(key, w.Bytes())
	return nil
}

func (c *customID) GetReservedCustomIDs(height uint32, info []RevertInfo) (map[string]struct{}, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getReservedCustomIDs(height, info)
}

func (c *customID) GetReceivedCustomIDs(height uint32, info []RevertInfo) (map[string]common.Uint168, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getReceivedCustomIDs(height, info)
}

func (c *customID) GetCustomIDFeeRate(height uint32) (common.Fixed64, error) {
	c.RLock()
	defer c.RUnlock()
	return c.getCustomIDFeeRate(height)
}

func (c *customID) getReservedCustomIDs(height uint32, info []RevertInfo) (map[string]struct{}, error) {
	if len(c.reservedCustomIDs) == 0 {
		ids, err := c.getReservedCustomIDsFromDB()
		if err != nil {
			return nil, err
		}
		// refresh the cache.
		c.reservedCustomIDs = ids
	}

	results := make(map[string]struct{})
	for k, v := range c.reservedCustomIDs {
		confirmCount := getConfirmCount(height, v, info)
		if confirmCount < DefaultConfirmations {
			continue
		}
		results[k] = struct{}{}
	}
	return results, nil
}

func getConfirmCount(currentHeight, proposalHeight uint32, info []RevertInfo) uint32 {
	if currentHeight <= proposalHeight {
		return 0
	}

	var lastMode byte
	var lastWorkingHeight uint32
	var confirmCount uint32
	var reachedTheEnd bool
	var beganFromStartHeight bool
	for _, r := range info {
		if proposalHeight < r.WorkingHeight {
			var calculateHeight uint32
			if currentHeight < r.WorkingHeight {
				calculateHeight = currentHeight
				reachedTheEnd = true
			} else {
				calculateHeight = r.WorkingHeight
			}

			if lastMode == byte(state.DPOS) {
				if proposalHeight > lastWorkingHeight {
					confirmCount += calculateHeight - proposalHeight
				} else {
					confirmCount += calculateHeight - lastWorkingHeight
				}
			}
			beganFromStartHeight = true
		}

		lastMode = r.Mode
		lastWorkingHeight = r.WorkingHeight

		if reachedTheEnd {
			break
		}
	}

	if lastMode == byte(state.DPOS) {
		if !beganFromStartHeight {
			confirmCount += currentHeight - proposalHeight
		} else if !reachedTheEnd {
			confirmCount += currentHeight - lastWorkingHeight
		}
	}

	return confirmCount
}

func maxUint32(first, second uint32) uint32 {
	if first < second {
		return second
	}

	return first
}

func (c *customID) getControversialReservedCustomIDsFromDB(proposalHash common.Uint256) (map[string]struct{}, error) {
	var val []byte
	val, err := c.db.Get(toKey(BKTReservedCustomID, proposalHash.Bytes()...), nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadVarUint(r, 0)
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

func (c *customID) getReservedCustomIDsFromDB() (map[string]uint32, error) {
	var val []byte
	//if return no err,reservedCustomIDs also allocated
	reservedCustomIDs := make(map[string]uint32, 0)
	val, err := c.db.Get(BKTReservedCustomID, nil)
	if err != nil {
		if err.Error() == leveldb.ErrNotFound.Error() {
			return reservedCustomIDs, nil
		}
		return nil, err
	}
	r := bytes.NewReader(val)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < count; i++ {
		id, err := common.ReadVarString(r)
		if err != nil {
			return nil, err
		}
		height, err := common.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		reservedCustomIDs[id] = height
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

func (c *customID) getReceivedCustomIDsFromDB() (map[string]CustomIDInfo, error) {
	var val []byte
	receiedCustomIDs := make(map[string]CustomIDInfo, 0)

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
		height, err := common.ReadUint32(r)
		if err != nil {
			return nil, err
		}
		receiedCustomIDs[id] = CustomIDInfo{
			DID:    did,
			Height: height,
		}
	}
	return receiedCustomIDs, nil
}

func (c *customID) getReceivedCustomIDs(height uint32, info []RevertInfo) (map[string]common.Uint168, error) {
	if len(c.receivedCustomIDs) == 0 {
		ids, err := c.getReceivedCustomIDsFromDB()
		if err != nil {
			return nil, err
		}
		// refresh the cache.
		c.receivedCustomIDs = ids
	}

	results := make(map[string]common.Uint168)
	for k, v := range c.receivedCustomIDs {
		confirmCount := getConfirmCount(height, v.Height, info)
		if confirmCount < DefaultConfirmations {
			continue
		}
		results[k] = v.DID
	}

	return results, nil
}

func (c *customID) getCustomIDFeeRate(height uint32) (common.Fixed64, error) {
	workingHeight, err := c.findCustomIDWorkingHeightByCurrentHeight(height)
	if err != nil {
		return 0, err
	}

	return c.getControversialCustomIDFeeRateByHeight(workingHeight)
}

func (c *customID) findCustomIDWorkingHeightByCurrentHeight(height uint32) (uint32, error) {
	var pos []uint32
	if len(c.customIDFeePosCache) == 0 {
		pos = c.getCurrentCustomIDFeePositions()
		c.customIDFeePosCache = pos
	} else {
		pos = c.customIDFeePosCache
	}

	if len(c.customIDFeePosCache) == 0 {
		return 0, errors.New("have no customID fee from main chain proposal")
	}

	for i := len(c.customIDFeePosCache) - 1; i >= 0; i-- {
		if height > c.customIDFeePosCache[i] {
			return c.customIDFeePosCache[i], nil
		}
	}

	return 0, nil
}

func (c *customID) getControversialCustomIDFeeRateByProposalHash(proposalHash common.Uint256) (common.Fixed64, uint32, error) {
	var val []byte
	val, err := c.db.Get(toKey(BKTChangeCustomIDFee, proposalHash.Bytes()...), nil)
	if err != nil {
		return 0, 0, err
	}
	r := bytes.NewReader(val)
	var rate common.Fixed64
	if err := rate.Deserialize(r); err != nil {
		return 0, 0, err
	}
	workingHeight, err := common.ReadUint32(r)
	if err != nil {
		return 0, 0, err
	}
	return rate, workingHeight, nil
}

func (c *customID) getControversialCustomIDFeeRateByHeight(workingHeight uint32) (common.Fixed64, error) {
	buf := new(bytes.Buffer)
	if err := common.WriteUint32(buf, workingHeight); err != nil {
		return 0, err
	}
	var val []byte
	val, err := c.db.Get(toKey(BKTChangeCustomIDFee, buf.Bytes()...), nil)
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

func (c *customID) BatchPutRetSideChainDepositCoinTx(tx *types.Transaction, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()
	for _, output := range tx.Outputs {

		//if this output is not OTReturnSideChainDepositCoin
		if output.Type != types.OTReturnSideChainDepositCoin {
			continue
		}
		outputPayload, ok := output.Payload.(*outputpayload.ReturnSideChainDeposit)
		if !ok {
			return errors.New("invalid ReturnSideChainDeposit output payload")
		}
		//if it is not this side chain
		if outputPayload.GenesisBlockAddress != c.GenesisBlockAddress {
			continue
		}
		batch.Put(toKey(BKTReturnSideChainDepositCoin, outputPayload.DepositTransactionHash.Bytes()...), []byte{1})
	}
	return nil
}

func (c *customID) BatchDeleteRetSideChainDepositCoinTx(tx *types.Transaction, batch *leveldb.Batch) error {
	c.Lock()
	defer c.Unlock()
	for _, output := range tx.Outputs {
		//if this output is not OTReturnSideChainDepositCoin
		if output.Type != types.OTReturnSideChainDepositCoin {
			continue
		}
		outputPayload, ok := output.Payload.(*outputpayload.ReturnSideChainDeposit)
		if !ok {
			return errors.New("invalid ReturnSideChainDeposit output payload")
		}
		//if it is not this side chain
		if outputPayload.GenesisBlockAddress != c.GenesisBlockAddress {
			continue
		}
		batch.Delete(toKey(BKTReturnSideChainDepositCoin, outputPayload.DepositTransactionHash.Bytes()...))
	}
	return nil
}

func (c *customID) HaveRetSideChainDepositCoinTx(txHash common.Uint256) bool {
	_, err := c.db.Get(toKey(BKTReturnSideChainDepositCoin, txHash.Bytes()...), nil)
	if err == nil {
		return true
	}
	return false
}
