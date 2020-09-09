// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
)

type ViewListener interface {
	OnViewChanged(isOnDuty bool, force bool)
}

const (
	ConsensusReady = iota
	ConsensusRunning
)

type ConsensusView struct {
	consensusStatus uint32
	viewOffset      uint32
	publicKey       []byte
	signTolerance   time.Duration
	viewStartTime   time.Time
	viewChangeTime  time.Time
	isDposOnDuty    bool
	producers       *Producers

	listener ViewListener
}

func (v *ConsensusView) resetViewOffset() {
	v.viewOffset = 0
}

func (v *ConsensusView) SetRunning() {
	v.consensusStatus = ConsensusRunning
}

func (v *ConsensusView) SetReady() {
	v.consensusStatus = ConsensusReady
}

func (v *ConsensusView) IsRunning() bool {
	return v.consensusStatus == ConsensusRunning
}

func (v *ConsensusView) IsReady() bool {
	return v.consensusStatus == ConsensusReady
}

func (v *ConsensusView) TryChangeView(now time.Time) {
	if v.IsRunning() && now.After(v.viewChangeTime) {
		Info("[TryChangeView] succeed", "now", now.String(), "changeTime", v.viewChangeTime.String())
		parentTime := float64(v.viewChangeTime.Unix()) - v.signTolerance.Seconds()
		v.ChangeView(now, false, uint64(parentTime))
	}
}

func (v *ConsensusView) GetProducers() [][]byte {
	return v.producers.GetProducers()
}

func (v *ConsensusView) calculateOffsetTime(startTime time.Time,
	now time.Time) (uint32, time.Duration) {
	duration := now.Sub(startTime)
	offset := duration / v.signTolerance
	offsetTime := duration % v.signTolerance

	return uint32(offset), offsetTime
}

func (v *ConsensusView) UpdateDutyIndex(height uint64) {
	v.producers.UpdateDutyIndex(height)

	currentProducer := v.producers.GetNextOnDutyProducer(v.viewOffset)
	v.isDposOnDuty = bytes.Equal(currentProducer, v.publicKey)
}

func (v *ConsensusView) ChangeView(now time.Time, force bool, parentTime uint64) {
	offset, offsetTime := v.calculateOffsetTime(v.viewStartTime, now)
	if offset > 0 {
		v.viewStartTime = now.Add(-offsetTime)
		v.ResetView(uint64(v.viewStartTime.Unix()))
	}
	v.viewOffset += offset
	if force {
		offset = 1
		v.resetViewOffset()
		v.ResetView(parentTime)
	}

	if offset > 0 {
		Info("\n\n\n--------------------Change View---------------------")
		Info("viewStartTime:", v.viewStartTime, "changeViewTime", v.viewChangeTime, "nowTime:", now, "offset:", offset, "offsetTime:", offsetTime, "force:", force,
			"viewOffset", v.viewOffset, "dutyIndex", v.producers.dutyIndex)
		currentProducer := v.producers.GetNextOnDutyProducer(v.viewOffset)
		v.isDposOnDuty = bytes.Equal(currentProducer, v.publicKey)
		v.DumpInfo()
		Info("\n\n\n")
		if v.listener != nil {
			v.listener.OnViewChanged(v.isDposOnDuty, force)
		}
	}
}

func (v *ConsensusView) DumpInfo() {
	str := "\n"
	for _, signer := range v.producers.producers {
		if v.ProducerIsOnDuty(signer) {
			duty := log.Color(log.Green, common.BytesToHexString(signer)+" onDuty \n")
			str = str + duty
		} else {
			str = str + common.BytesToHexString(signer) + " not onDuty \n"
		}
	}
	Info(str)
}

func (v *ConsensusView) GetViewInterval() time.Duration {
	return v.signTolerance
}

func (v *ConsensusView) GetViewStartTime() time.Time {
	return v.viewStartTime
}

func (v *ConsensusView) GetChangeViewTime() time.Time {
	return v.viewChangeTime
}

func (v *ConsensusView) GetViewOffset() uint32 {
	return v.viewOffset
}

func (v *ConsensusView) ResetView(parentTime uint64) {
	v.SetChangViewTime(parentTime)
}

func (v *ConsensusView) SetChangViewTime(parentTime uint64) {
	headerTime := time.Unix(int64(parentTime), 0)
	v.viewChangeTime = headerTime.Add(v.signTolerance)
	v.viewStartTime = headerTime
}

func (v *ConsensusView) IsProducers(account []byte) bool {
	return v.producers.IsProducers(account)
}

func (v *ConsensusView) IsOnduty() bool {
	return v.isDposOnDuty
}

func (v *ConsensusView) ProducerIsOnDuty(account []byte) bool {
	producer := v.producers.GetNextOnDutyProducer(v.viewOffset)
	return bytes.Equal(producer, account)
}

func (v *ConsensusView) IsMajorityAgree(count int) bool {
	return v.producers.IsMajorityAgree(count)
}

func (v *ConsensusView) IsMajorityRejected(count int) bool {
	return v.producers.IsMajorityRejected(count)
}

func (v *ConsensusView) HasArbitersMinorityCount(count int) bool {
	return v.producers.HasArbitersMinorityCount(count)
}

func (v *ConsensusView) HasProducerMajorityCount(count int) bool {
	return v.producers.HasProducerMajorityCount(count)
}

func (v *ConsensusView) GetMajorityCount() int {
	return v.producers.GetMajorityCount()
}

func NewConsensusView(tolerance time.Duration, account []byte,
	producers *Producers, viewListener ViewListener) *ConsensusView {
	c := &ConsensusView{
		consensusStatus: ConsensusReady,
		viewStartTime:   time.Unix(0, 0),
		viewOffset:      0,
		publicKey:       account,
		signTolerance:   tolerance,
		producers:       producers,
		listener:        viewListener,
		isDposOnDuty:    false,
	}
	return c
}
