package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/elastos/Elastos.ELA.SPV/util"

	elatx "github.com/elastos/Elastos.ELA/core/transaction"
	elacommon "github.com/elastos/Elastos.ELA/core/types/common"
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/syndtr/goleveldb/leveldb"
)

// Ensure dataBatch implement DataBatch interface.
var _ DataBatch = (*dataBatch)(nil)

type dataBatch struct {
	mutex sync.Mutex
	*leveldb.DB
	*customID
	*leveldb.Batch
}

func (b *dataBatch) Txs() TxsBatch {
	return &txsBatch{DB: b.DB, Batch: b.Batch}
}

func (b *dataBatch) Ops() OpsBatch {
	return &opsBatch{DB: b.DB, Batch: b.Batch}
}

func (b *dataBatch) Que() QueBatch {
	return &queBatch{DB: b.DB, Batch: b.Batch}
}

func (b *dataBatch) GetNakedBatch() *leveldb.Batch {
	return b.Batch
}

// Delete all transactions, ops, queued items on the given height.
func (b *dataBatch) DelAll(height uint32) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	var key [4]byte
	binary.BigEndian.PutUint32(key[:], height)
	data, _ := b.DB.Get(toKey(BKTHeightTxs, key[:]...), nil)
	for _, txId := range getTxIds(data) {
		var utx util.Tx
		data, err := b.DB.Get(toKey(BKTTxs, txId.Bytes()...), nil)
		if err != nil {
			return err
		}
		if err := utx.Deserialize(bytes.NewReader(data)); err != nil {
			return err
		}

		r := bytes.NewReader(utx.RawData)
		tx, err := elatx.GetTransactionByBytes(r)
		if err != nil {
			return fmt.Errorf("deseralize transaction file failed, error %s", err.Error())
		}
		err = tx.Deserialize(r)
		if err != nil {
			return err
		}

		// remove custom ID related data.
		err = b.DeleteCustomID(tx)
		if err != nil {
			return err
		}

		for index := range tx.Outputs() {
			outpoint := elacommon.NewOutPoint(utx.Hash, uint16(index))
			b.Batch.Delete(toKey(BKTOps, outpoint.Bytes()...))
		}

		b.Batch.Delete(toKey(BKTTxs, txId.Bytes()...))
	}

	b.Batch.Delete(toKey(BKTHeightTxs, key[:]...))

	return b.Que().DelAll(height)
}

func (b *dataBatch) DeleteCustomID(tx it.Transaction) error {
	switch tx.TxType() {
	case elacommon.ReturnSideChainDepositCoin:
		_, ok := tx.Payload().(*payload.ReturnSideChainDepositCoin)
		if !ok {
			return errors.New("invalid ReturnSideChainDepositCoin tx")
		}
		b.customID.BatchDeleteRetSideChainDepositCoinTx(tx, b.Batch)
	case elacommon.CRCProposal:
		p, ok := tx.Payload().(*payload.CRCProposal)
		if !ok {
			return errors.New("invalid crc proposal tx")
		}
		switch p.ProposalType {
		case payload.ReserveCustomID:
			b.customID.BatchDeleteControversialReservedCustomIDs(
				p.Hash(tx.PayloadVersion()), b.Batch)
		case payload.ReceiveCustomID:
			b.customID.BatchDeleteControversialReceivedCustomIDs(
				p.Hash(tx.PayloadVersion()), b.Batch)
		case payload.ChangeCustomIDFee:
			b.customID.BatchDeleteControversialChangeCustomIDFee(
				p.Hash(tx.PayloadVersion()), b.Batch)
		}
	case elacommon.ProposalResult:
		p, ok := tx.Payload().(*payload.RecordProposalResult)
		if !ok {
			return errors.New("invalid custom ID result tx")
		}

		for _, r := range p.ProposalResults {
			switch r.ProposalType {
			case payload.ReserveCustomID:
				// initialize cache.
				if len(b.customID.reservedCustomIDs) == 0 {
					existedCustomIDs, err := b.customID.getReservedCustomIDsFromDB()
					if err != nil {
						return err
					}
					b.customID.reservedCustomIDs = existedCustomIDs
				}
				if r.Result == true {
					// update cache.
					reservedCustomIDs, err := b.customID.getControversialReservedCustomIDsFromDB(r.ProposalHash)
					if err != nil {
						return err
					}
					for k, _ := range reservedCustomIDs {
						delete(b.customID.reservedCustomIDs, k)
					}
					// update db.
					if err := b.customID.batchPutReservedCustomIDs(b.Batch); err != nil {
						return err
					}
				}

			case payload.ReceiveCustomID:
				// initialize cache.
				if len(b.customID.receivedCustomIDs) == 0 {
					existedCustomIDs, err := b.customID.getReceivedCustomIDsFromDB()
					if err != nil {
						return err
					}
					b.customID.receivedCustomIDs = existedCustomIDs
				}
				if r.Result == true {
					// update cache.
					receivedCustomIDs, err := b.customID.getControversialReceivedCustomIDsFromDB(r.ProposalHash)
					if err != nil {
						return err
					}
					for k, _ := range receivedCustomIDs {
						delete(b.customID.receivedCustomIDs, k)
					}
					// update db.
					if err := b.customID.batchPutReceivedCustomIDs(b.Batch); err != nil {
						return err
					}
				}

			case payload.ChangeCustomIDFee:
				// reorganize: no need to change data of database, because
				// the data of workingHeight will be rewrite later.
			}
		}
	}
	return nil
}

func (b *dataBatch) Commit() error {
	return b.DB.Write(b.Batch, nil)
}

func (b *dataBatch) Rollback() error {
	b.Batch.Reset()
	return nil
}
