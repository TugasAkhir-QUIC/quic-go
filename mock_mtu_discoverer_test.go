// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go (interfaces: MTUDiscoverer)
//
// Generated by this command:
//
//	mockgen.exe -typed -build_flags=-tags=gomock -package quic -self_package github.com/quic-go/quic-go -destination mock_mtu_discoverer_test.go github.com/quic-go/quic-go MTUDiscoverer
//
// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"
	time "time"

	ackhandler "github.com/quic-go/quic-go/internal/ackhandler"
	protocol "github.com/quic-go/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockMTUDiscoverer is a mock of MTUDiscoverer interface.
type MockMTUDiscoverer struct {
	ctrl     *gomock.Controller
	recorder *MockMTUDiscovererMockRecorder
}

// MockMTUDiscovererMockRecorder is the mock recorder for MockMTUDiscoverer.
type MockMTUDiscovererMockRecorder struct {
	mock *MockMTUDiscoverer
}

// NewMockMTUDiscoverer creates a new mock instance.
func NewMockMTUDiscoverer(ctrl *gomock.Controller) *MockMTUDiscoverer {
	mock := &MockMTUDiscoverer{ctrl: ctrl}
	mock.recorder = &MockMTUDiscovererMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMTUDiscoverer) EXPECT() *MockMTUDiscovererMockRecorder {
	return m.recorder
}

// CurrentSize mocks base method.
func (m *MockMTUDiscoverer) CurrentSize() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// CurrentSize indicates an expected call of CurrentSize.
func (mr *MockMTUDiscovererMockRecorder) CurrentSize() *MTUDiscovererCurrentSizeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentSize", reflect.TypeOf((*MockMTUDiscoverer)(nil).CurrentSize))
	return &MTUDiscovererCurrentSizeCall{Call: call}
}

// MTUDiscovererCurrentSizeCall wrap *gomock.Call
type MTUDiscovererCurrentSizeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MTUDiscovererCurrentSizeCall) Return(arg0 protocol.ByteCount) *MTUDiscovererCurrentSizeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MTUDiscovererCurrentSizeCall) Do(f func() protocol.ByteCount) *MTUDiscovererCurrentSizeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MTUDiscovererCurrentSizeCall) DoAndReturn(f func() protocol.ByteCount) *MTUDiscovererCurrentSizeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPing mocks base method.
func (m *MockMTUDiscoverer) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPing")
	ret0, _ := ret[0].(ackhandler.Frame)
	ret1, _ := ret[1].(protocol.ByteCount)
	return ret0, ret1
}

// GetPing indicates an expected call of GetPing.
func (mr *MockMTUDiscovererMockRecorder) GetPing() *MTUDiscovererGetPingCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPing", reflect.TypeOf((*MockMTUDiscoverer)(nil).GetPing))
	return &MTUDiscovererGetPingCall{Call: call}
}

// MTUDiscovererGetPingCall wrap *gomock.Call
type MTUDiscovererGetPingCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MTUDiscovererGetPingCall) Return(arg0 ackhandler.Frame, arg1 protocol.ByteCount) *MTUDiscovererGetPingCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MTUDiscovererGetPingCall) Do(f func() (ackhandler.Frame, protocol.ByteCount)) *MTUDiscovererGetPingCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MTUDiscovererGetPingCall) DoAndReturn(f func() (ackhandler.Frame, protocol.ByteCount)) *MTUDiscovererGetPingCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ShouldSendProbe mocks base method.
func (m *MockMTUDiscoverer) ShouldSendProbe(arg0 time.Time) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShouldSendProbe", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// ShouldSendProbe indicates an expected call of ShouldSendProbe.
func (mr *MockMTUDiscovererMockRecorder) ShouldSendProbe(arg0 any) *MTUDiscovererShouldSendProbeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShouldSendProbe", reflect.TypeOf((*MockMTUDiscoverer)(nil).ShouldSendProbe), arg0)
	return &MTUDiscovererShouldSendProbeCall{Call: call}
}

// MTUDiscovererShouldSendProbeCall wrap *gomock.Call
type MTUDiscovererShouldSendProbeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MTUDiscovererShouldSendProbeCall) Return(arg0 bool) *MTUDiscovererShouldSendProbeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MTUDiscovererShouldSendProbeCall) Do(f func(time.Time) bool) *MTUDiscovererShouldSendProbeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MTUDiscovererShouldSendProbeCall) DoAndReturn(f func(time.Time) bool) *MTUDiscovererShouldSendProbeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Start mocks base method.
func (m *MockMTUDiscoverer) Start(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Start", arg0)
}

// Start indicates an expected call of Start.
func (mr *MockMTUDiscovererMockRecorder) Start(arg0 any) *MTUDiscovererStartCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockMTUDiscoverer)(nil).Start), arg0)
	return &MTUDiscovererStartCall{Call: call}
}

// MTUDiscovererStartCall wrap *gomock.Call
type MTUDiscovererStartCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MTUDiscovererStartCall) Return() *MTUDiscovererStartCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MTUDiscovererStartCall) Do(f func(protocol.ByteCount)) *MTUDiscovererStartCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MTUDiscovererStartCall) DoAndReturn(f func(protocol.ByteCount)) *MTUDiscovererStartCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
