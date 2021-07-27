package core


import (
	"io"
	"os"
	"path/filepath"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
)

const jouralFileName = "evilsignerevents.rlp"

// EvilJournal is a rotating log of evilSingerEvents with the aim of storing locally
// created transactions to allow non-executed ones to survive node restarts.
type EvilJournal struct {
	path   string         // Filesystem path to store the evilSingerEvents at
	writer io.WriteCloser // Output stream to write new evilSingerEvents into
}

// NewEvilJournal creates a new evilSingerEvent journal to
func NewEvilJournal(dir string) *EvilJournal {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	path := filepath.Join(dir, jouralFileName)
	return &EvilJournal{
		path: path,
	}
}

// load parses a evilSingerEvent journal dump from disk, loading its contents into
// the specified pool.
func (journal *EvilJournal) Load(add func([]*EvilSingerEvent) []error) error {
	// Skip the parsing if the journal file doesn't exist at all
	if _, err := os.Stat(journal.path); os.IsNotExist(err) {
		return nil
	}
	// Open the journal for loading any past evilSingerEvents
	input, err := os.Open(journal.path)
	if err != nil {
		return err
	}
	defer input.Close()

	// Temporarily discard any journal additions (don't double add on load)
	journal.writer = new(devNull)
	defer func() { journal.writer = nil }()

	// Inject all transactions from the journal into the pool
	stream := rlp.NewStream(input, 0)
	total, dropped := 0, 0

	// Create a method to load a limited batch of evilSingerEvents and bump the
	// appropriate progress counters. Then use this method to load all the
	// journaled evilSingerEvents in small-ish batches.
	loadBatch := func(evilEvents []*EvilSingerEvent) {
		for _, err := range add(evilEvents) {
			if err != nil {
				log.Debug("Failed to add journaled evilSignerEvent", "err", err)
				dropped++
			}
		}
	}

	var (
		failure error
		batch   []*EvilSingerEvent
	)

	for {
		// Parse the next evilSingerEvent and terminate on error
		evilEvent := new(EvilSingerEvent)
		if err := stream.Decode(evilEvent); err != nil {
			if err != io.EOF {
				failure = err
			}
			if len(batch) > 0 {
				loadBatch(batch)
			}
			break
		}
		// New evilSingerEvent parsed, queue up for later, import if threshold is reached
		total++

		if batch = append(batch, evilEvent); len(batch) > 100 {
			loadBatch(batch)
			batch = batch[:0]
		}

	}
	log.Info("Loaded local evilSingerEvent journal", "evilSingerEvents", total, "dropped", dropped)

	return failure
}

// insert adds the specified evilSingerEvent to the local disk journal.
func (journal *EvilJournal) Insert(evilEvent *EvilSingerEvent) error {

	if journal.writer == nil {
		return errNoActiveJournal
	}
	if err := rlp.Encode(journal.writer, evilEvent); err != nil {
		return err
	}
	return nil
}

// rotate regenerates the evilSingerEvent journal based on the current contents of blockChain.EvilSignersMap
func (journal *EvilJournal) Rotate(all []*EvilSingerEvent) error {

	if journal.writer != nil {
		if err := journal.writer.Close(); err != nil {
			return err
		}
		journal.writer = nil
	}

	replacement, err := os.OpenFile(journal.path+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	journaled := 0
	for _, evilevent := range all {
		if err = rlp.Encode(replacement, evilevent); err != nil {
			replacement.Close()
			return err
		}
		journaled++
	}
	replacement.Close()

	if err = os.Rename(journal.path+".new", journal.path); err != nil {
		return err
	}

	sink, err := os.OpenFile(journal.path, os.O_WRONLY|os.O_APPEND, 0755)
	if err != nil {
		return err
	}
	journal.writer = sink
	log.Info("Regenerated local evilSingerEvent journal", "evilSingerEvents", journaled, "base", len(all))

	return nil

}

// close flushes the evilSingerEvent journal contents to disk and closes the file.
func (journal *EvilJournal) Close() error {
	var err error
	if journal.writer != nil {
		err = journal.writer.Close()
		journal.writer = nil
	}
	return err
}
