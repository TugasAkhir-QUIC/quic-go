// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go/internal/handshake (interfaces: ShortHeaderOpener)
//
// Generated by this command:
//
//	mockgen.exe -typed -build_flags=-tags=gomock -package mocks -destination short_header_opener.go github.com/quic-go/quic-go/internal/handshake ShortHeaderOpener
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"
	time "time"

	protocol "github.com/quic-go/quic-go/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockShortHeaderOpener is a mock of ShortHeaderOpener interface.
type MockShortHeaderOpener struct {
	ctrl     *gomock.Controller
	recorder *MockShortHeaderOpenerMockRecorder
}

// MockShortHeaderOpenerMockRecorder is the mock recorder for MockShortHeaderOpener.
type MockShortHeaderOpenerMockRecorder struct {
	mock *MockShortHeaderOpener
}

// NewMockShortHeaderOpener creates a new mock instance.
func NewMockShortHeaderOpener(ctrl *gomock.Controller) *MockShortHeaderOpener {
	mock := &MockShortHeaderOpener{ctrl: ctrl}
	mock.recorder = &MockShortHeaderOpenerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockShortHeaderOpener) EXPECT() *MockShortHeaderOpenerMockRecorder {
	return m.recorder
}

// DecodePacketNumber mocks base method.
func (m *MockShortHeaderOpener) DecodePacketNumber(arg0 protocol.PacketNumber, arg1 protocol.PacketNumberLen) protocol.PacketNumber {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecodePacketNumber", arg0, arg1)
	ret0, _ := ret[0].(protocol.PacketNumber)
	return ret0
}

// DecodePacketNumber indicates an expected call of DecodePacketNumber.
func (mr *MockShortHeaderOpenerMockRecorder) DecodePacketNumber(arg0, arg1 any) *ShortHeaderOpenerDecodePacketNumberCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecodePacketNumber", reflect.TypeOf((*MockShortHeaderOpener)(nil).DecodePacketNumber), arg0, arg1)
	return &ShortHeaderOpenerDecodePacketNumberCall{Call: call}
}

// ShortHeaderOpenerDecodePacketNumberCall wrap *gomock.Call
type ShortHeaderOpenerDecodePacketNumberCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderOpenerDecodePacketNumberCall) Return(arg0 protocol.PacketNumber) *ShortHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderOpenerDecodePacketNumberCall) Do(f func(protocol.PacketNumber, protocol.PacketNumberLen) protocol.PacketNumber) *ShortHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderOpenerDecodePacketNumberCall) DoAndReturn(f func(protocol.PacketNumber, protocol.PacketNumberLen) protocol.PacketNumber) *ShortHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// DecryptHeader mocks base method.
func (m *MockShortHeaderOpener) DecryptHeader(arg0 []byte, arg1 *byte, arg2 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DecryptHeader", arg0, arg1, arg2)
}

// DecryptHeader indicates an expected call of DecryptHeader.
func (mr *MockShortHeaderOpenerMockRecorder) DecryptHeader(arg0, arg1, arg2 any) *ShortHeaderOpenerDecryptHeaderCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptHeader", reflect.TypeOf((*MockShortHeaderOpener)(nil).DecryptHeader), arg0, arg1, arg2)
	return &ShortHeaderOpenerDecryptHeaderCall{Call: call}
}

// ShortHeaderOpenerDecryptHeaderCall wrap *gomock.Call
type ShortHeaderOpenerDecryptHeaderCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderOpenerDecryptHeaderCall) Return() *ShortHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderOpenerDecryptHeaderCall) Do(f func([]byte, *byte, []byte)) *ShortHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderOpenerDecryptHeaderCall) DoAndReturn(f func([]byte, *byte, []byte)) *ShortHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Open mocks base method.
func (m *MockShortHeaderOpener) Open(arg0, arg1 []byte, arg2 time.Time, arg3 protocol.PacketNumber, arg4 protocol.KeyPhaseBit, arg5 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Open", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Open indicates an expected call of Open.
func (mr *MockShortHeaderOpenerMockRecorder) Open(arg0, arg1, arg2, arg3, arg4, arg5 any) *ShortHeaderOpenerOpenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Open", reflect.TypeOf((*MockShortHeaderOpener)(nil).Open), arg0, arg1, arg2, arg3, arg4, arg5)
	return &ShortHeaderOpenerOpenCall{Call: call}
}

// ShortHeaderOpenerOpenCall wrap *gomock.Call
type ShortHeaderOpenerOpenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ShortHeaderOpenerOpenCall) Return(arg0 []byte, arg1 error) *ShortHeaderOpenerOpenCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ShortHeaderOpenerOpenCall) Do(f func([]byte, []byte, time.Time, protocol.PacketNumber, protocol.KeyPhaseBit, []byte) ([]byte, error)) *ShortHeaderOpenerOpenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ShortHeaderOpenerOpenCall) DoAndReturn(f func([]byte, []byte, time.Time, protocol.PacketNumber, protocol.KeyPhaseBit, []byte) ([]byte, error)) *ShortHeaderOpenerOpenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
