// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go (interfaces: EarlyConnection)
//
// Generated by this command:
//
//	mockgen.exe -typed -build_flags=-tags=gomock -package mockquic -destination quic/early_conn_tmp.go github.com/quic-go/quic-go EarlyConnection
//
// Package mockquic is a generated GoMock package.
package mockquic

import (
	context "context"
	net "net"
	reflect "reflect"

	quic "github.com/quic-go/quic-go"
	qerr "github.com/quic-go/quic-go/internal/qerr"
	gomock "go.uber.org/mock/gomock"
)

// MockEarlyConnection is a mock of EarlyConnection interface.
type MockEarlyConnection struct {
	ctrl     *gomock.Controller
	recorder *MockEarlyConnectionMockRecorder
}

// MockEarlyConnectionMockRecorder is the mock recorder for MockEarlyConnection.
type MockEarlyConnectionMockRecorder struct {
	mock *MockEarlyConnection
}

// NewMockEarlyConnection creates a new mock instance.
func NewMockEarlyConnection(ctrl *gomock.Controller) *MockEarlyConnection {
	mock := &MockEarlyConnection{ctrl: ctrl}
	mock.recorder = &MockEarlyConnectionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEarlyConnection) EXPECT() *MockEarlyConnectionMockRecorder {
	return m.recorder
}

// AcceptStream mocks base method.
func (m *MockEarlyConnection) AcceptStream(arg0 context.Context) (quic.Stream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AcceptStream", arg0)
	ret0, _ := ret[0].(quic.Stream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AcceptStream indicates an expected call of AcceptStream.
func (mr *MockEarlyConnectionMockRecorder) AcceptStream(arg0 any) *EarlyConnectionAcceptStreamCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AcceptStream", reflect.TypeOf((*MockEarlyConnection)(nil).AcceptStream), arg0)
	return &EarlyConnectionAcceptStreamCall{Call: call}
}

// EarlyConnectionAcceptStreamCall wrap *gomock.Call
type EarlyConnectionAcceptStreamCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionAcceptStreamCall) Return(arg0 quic.Stream, arg1 error) *EarlyConnectionAcceptStreamCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionAcceptStreamCall) Do(f func(context.Context) (quic.Stream, error)) *EarlyConnectionAcceptStreamCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionAcceptStreamCall) DoAndReturn(f func(context.Context) (quic.Stream, error)) *EarlyConnectionAcceptStreamCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AcceptUniStream mocks base method.
func (m *MockEarlyConnection) AcceptUniStream(arg0 context.Context) (quic.ReceiveStream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AcceptUniStream", arg0)
	ret0, _ := ret[0].(quic.ReceiveStream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AcceptUniStream indicates an expected call of AcceptUniStream.
func (mr *MockEarlyConnectionMockRecorder) AcceptUniStream(arg0 any) *EarlyConnectionAcceptUniStreamCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AcceptUniStream", reflect.TypeOf((*MockEarlyConnection)(nil).AcceptUniStream), arg0)
	return &EarlyConnectionAcceptUniStreamCall{Call: call}
}

// EarlyConnectionAcceptUniStreamCall wrap *gomock.Call
type EarlyConnectionAcceptUniStreamCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionAcceptUniStreamCall) Return(arg0 quic.ReceiveStream, arg1 error) *EarlyConnectionAcceptUniStreamCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionAcceptUniStreamCall) Do(f func(context.Context) (quic.ReceiveStream, error)) *EarlyConnectionAcceptUniStreamCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionAcceptUniStreamCall) DoAndReturn(f func(context.Context) (quic.ReceiveStream, error)) *EarlyConnectionAcceptUniStreamCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// CloseWithError mocks base method.
func (m *MockEarlyConnection) CloseWithError(arg0 qerr.ApplicationErrorCode, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseWithError", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseWithError indicates an expected call of CloseWithError.
func (mr *MockEarlyConnectionMockRecorder) CloseWithError(arg0, arg1 any) *EarlyConnectionCloseWithErrorCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseWithError", reflect.TypeOf((*MockEarlyConnection)(nil).CloseWithError), arg0, arg1)
	return &EarlyConnectionCloseWithErrorCall{Call: call}
}

// EarlyConnectionCloseWithErrorCall wrap *gomock.Call
type EarlyConnectionCloseWithErrorCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionCloseWithErrorCall) Return(arg0 error) *EarlyConnectionCloseWithErrorCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionCloseWithErrorCall) Do(f func(qerr.ApplicationErrorCode, string) error) *EarlyConnectionCloseWithErrorCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionCloseWithErrorCall) DoAndReturn(f func(qerr.ApplicationErrorCode, string) error) *EarlyConnectionCloseWithErrorCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ConnectionState mocks base method.
func (m *MockEarlyConnection) ConnectionState() quic.ConnectionState {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConnectionState")
	ret0, _ := ret[0].(quic.ConnectionState)
	return ret0
}

// ConnectionState indicates an expected call of ConnectionState.
func (mr *MockEarlyConnectionMockRecorder) ConnectionState() *EarlyConnectionConnectionStateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConnectionState", reflect.TypeOf((*MockEarlyConnection)(nil).ConnectionState))
	return &EarlyConnectionConnectionStateCall{Call: call}
}

// EarlyConnectionConnectionStateCall wrap *gomock.Call
type EarlyConnectionConnectionStateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionConnectionStateCall) Return(arg0 quic.ConnectionState) *EarlyConnectionConnectionStateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionConnectionStateCall) Do(f func() quic.ConnectionState) *EarlyConnectionConnectionStateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionConnectionStateCall) DoAndReturn(f func() quic.ConnectionState) *EarlyConnectionConnectionStateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Context mocks base method.
func (m *MockEarlyConnection) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockEarlyConnectionMockRecorder) Context() *EarlyConnectionContextCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockEarlyConnection)(nil).Context))
	return &EarlyConnectionContextCall{Call: call}
}

// EarlyConnectionContextCall wrap *gomock.Call
type EarlyConnectionContextCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionContextCall) Return(arg0 context.Context) *EarlyConnectionContextCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionContextCall) Do(f func() context.Context) *EarlyConnectionContextCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionContextCall) DoAndReturn(f func() context.Context) *EarlyConnectionContextCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetMaxBandwidth mocks base method.
func (m *MockEarlyConnection) GetMaxBandwidth() uint64 {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMaxBandwidth")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetMaxBandwidth indicates an expected call of GetMaxBandwidth.
func (mr *MockEarlyConnectionMockRecorder) GetMaxBandwidth() *EarlyConnectionGetMaxBandwidthCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMaxBandwidth", reflect.TypeOf((*MockEarlyConnection)(nil).GetMaxBandwidth))
	return &EarlyConnectionGetMaxBandwidthCall{Call: call}
}

// EarlyConnectionGetMaxBandwidthCall wrap *gomock.Call
type EarlyConnectionGetMaxBandwidthCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionGetMaxBandwidthCall) Return(arg0 uint64) *EarlyConnectionGetMaxBandwidthCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionGetMaxBandwidthCall) Do(f func() uint64) *EarlyConnectionGetMaxBandwidthCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionGetMaxBandwidthCall) DoAndReturn(f func() uint64) *EarlyConnectionGetMaxBandwidthCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// HandshakeComplete mocks base method.
func (m *MockEarlyConnection) HandshakeComplete() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandshakeComplete")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// HandshakeComplete indicates an expected call of HandshakeComplete.
func (mr *MockEarlyConnectionMockRecorder) HandshakeComplete() *EarlyConnectionHandshakeCompleteCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandshakeComplete", reflect.TypeOf((*MockEarlyConnection)(nil).HandshakeComplete))
	return &EarlyConnectionHandshakeCompleteCall{Call: call}
}

// EarlyConnectionHandshakeCompleteCall wrap *gomock.Call
type EarlyConnectionHandshakeCompleteCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionHandshakeCompleteCall) Return(arg0 <-chan struct{}) *EarlyConnectionHandshakeCompleteCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionHandshakeCompleteCall) Do(f func() <-chan struct{}) *EarlyConnectionHandshakeCompleteCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionHandshakeCompleteCall) DoAndReturn(f func() <-chan struct{}) *EarlyConnectionHandshakeCompleteCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// LocalAddr mocks base method.
func (m *MockEarlyConnection) LocalAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// LocalAddr indicates an expected call of LocalAddr.
func (mr *MockEarlyConnectionMockRecorder) LocalAddr() *EarlyConnectionLocalAddrCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalAddr", reflect.TypeOf((*MockEarlyConnection)(nil).LocalAddr))
	return &EarlyConnectionLocalAddrCall{Call: call}
}

// EarlyConnectionLocalAddrCall wrap *gomock.Call
type EarlyConnectionLocalAddrCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionLocalAddrCall) Return(arg0 net.Addr) *EarlyConnectionLocalAddrCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionLocalAddrCall) Do(f func() net.Addr) *EarlyConnectionLocalAddrCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionLocalAddrCall) DoAndReturn(f func() net.Addr) *EarlyConnectionLocalAddrCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// NextConnection mocks base method.
func (m *MockEarlyConnection) NextConnection() quic.Connection {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NextConnection")
	ret0, _ := ret[0].(quic.Connection)
	return ret0
}

// NextConnection indicates an expected call of NextConnection.
func (mr *MockEarlyConnectionMockRecorder) NextConnection() *EarlyConnectionNextConnectionCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NextConnection", reflect.TypeOf((*MockEarlyConnection)(nil).NextConnection))
	return &EarlyConnectionNextConnectionCall{Call: call}
}

// EarlyConnectionNextConnectionCall wrap *gomock.Call
type EarlyConnectionNextConnectionCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionNextConnectionCall) Return(arg0 quic.Connection) *EarlyConnectionNextConnectionCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionNextConnectionCall) Do(f func() quic.Connection) *EarlyConnectionNextConnectionCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionNextConnectionCall) DoAndReturn(f func() quic.Connection) *EarlyConnectionNextConnectionCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OpenStream mocks base method.
func (m *MockEarlyConnection) OpenStream() (quic.Stream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenStream")
	ret0, _ := ret[0].(quic.Stream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenStream indicates an expected call of OpenStream.
func (mr *MockEarlyConnectionMockRecorder) OpenStream() *EarlyConnectionOpenStreamCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenStream", reflect.TypeOf((*MockEarlyConnection)(nil).OpenStream))
	return &EarlyConnectionOpenStreamCall{Call: call}
}

// EarlyConnectionOpenStreamCall wrap *gomock.Call
type EarlyConnectionOpenStreamCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionOpenStreamCall) Return(arg0 quic.Stream, arg1 error) *EarlyConnectionOpenStreamCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionOpenStreamCall) Do(f func() (quic.Stream, error)) *EarlyConnectionOpenStreamCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionOpenStreamCall) DoAndReturn(f func() (quic.Stream, error)) *EarlyConnectionOpenStreamCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OpenStreamSync mocks base method.
func (m *MockEarlyConnection) OpenStreamSync(arg0 context.Context) (quic.Stream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenStreamSync", arg0)
	ret0, _ := ret[0].(quic.Stream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenStreamSync indicates an expected call of OpenStreamSync.
func (mr *MockEarlyConnectionMockRecorder) OpenStreamSync(arg0 any) *EarlyConnectionOpenStreamSyncCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenStreamSync", reflect.TypeOf((*MockEarlyConnection)(nil).OpenStreamSync), arg0)
	return &EarlyConnectionOpenStreamSyncCall{Call: call}
}

// EarlyConnectionOpenStreamSyncCall wrap *gomock.Call
type EarlyConnectionOpenStreamSyncCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionOpenStreamSyncCall) Return(arg0 quic.Stream, arg1 error) *EarlyConnectionOpenStreamSyncCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionOpenStreamSyncCall) Do(f func(context.Context) (quic.Stream, error)) *EarlyConnectionOpenStreamSyncCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionOpenStreamSyncCall) DoAndReturn(f func(context.Context) (quic.Stream, error)) *EarlyConnectionOpenStreamSyncCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OpenUniStream mocks base method.
func (m *MockEarlyConnection) OpenUniStream() (quic.SendStream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenUniStream")
	ret0, _ := ret[0].(quic.SendStream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenUniStream indicates an expected call of OpenUniStream.
func (mr *MockEarlyConnectionMockRecorder) OpenUniStream() *EarlyConnectionOpenUniStreamCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenUniStream", reflect.TypeOf((*MockEarlyConnection)(nil).OpenUniStream))
	return &EarlyConnectionOpenUniStreamCall{Call: call}
}

// EarlyConnectionOpenUniStreamCall wrap *gomock.Call
type EarlyConnectionOpenUniStreamCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionOpenUniStreamCall) Return(arg0 quic.SendStream, arg1 error) *EarlyConnectionOpenUniStreamCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionOpenUniStreamCall) Do(f func() (quic.SendStream, error)) *EarlyConnectionOpenUniStreamCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionOpenUniStreamCall) DoAndReturn(f func() (quic.SendStream, error)) *EarlyConnectionOpenUniStreamCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OpenUniStreamSync mocks base method.
func (m *MockEarlyConnection) OpenUniStreamSync(arg0 context.Context) (quic.SendStream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenUniStreamSync", arg0)
	ret0, _ := ret[0].(quic.SendStream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenUniStreamSync indicates an expected call of OpenUniStreamSync.
func (mr *MockEarlyConnectionMockRecorder) OpenUniStreamSync(arg0 any) *EarlyConnectionOpenUniStreamSyncCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenUniStreamSync", reflect.TypeOf((*MockEarlyConnection)(nil).OpenUniStreamSync), arg0)
	return &EarlyConnectionOpenUniStreamSyncCall{Call: call}
}

// EarlyConnectionOpenUniStreamSyncCall wrap *gomock.Call
type EarlyConnectionOpenUniStreamSyncCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionOpenUniStreamSyncCall) Return(arg0 quic.SendStream, arg1 error) *EarlyConnectionOpenUniStreamSyncCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionOpenUniStreamSyncCall) Do(f func(context.Context) (quic.SendStream, error)) *EarlyConnectionOpenUniStreamSyncCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionOpenUniStreamSyncCall) DoAndReturn(f func(context.Context) (quic.SendStream, error)) *EarlyConnectionOpenUniStreamSyncCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReceiveDatagram mocks base method.
func (m *MockEarlyConnection) ReceiveDatagram(arg0 context.Context) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReceiveDatagram", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReceiveDatagram indicates an expected call of ReceiveDatagram.
func (mr *MockEarlyConnectionMockRecorder) ReceiveDatagram(arg0 any) *EarlyConnectionReceiveDatagramCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReceiveDatagram", reflect.TypeOf((*MockEarlyConnection)(nil).ReceiveDatagram), arg0)
	return &EarlyConnectionReceiveDatagramCall{Call: call}
}

// EarlyConnectionReceiveDatagramCall wrap *gomock.Call
type EarlyConnectionReceiveDatagramCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionReceiveDatagramCall) Return(arg0 []byte, arg1 error) *EarlyConnectionReceiveDatagramCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionReceiveDatagramCall) Do(f func(context.Context) ([]byte, error)) *EarlyConnectionReceiveDatagramCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionReceiveDatagramCall) DoAndReturn(f func(context.Context) ([]byte, error)) *EarlyConnectionReceiveDatagramCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// RemoteAddr mocks base method.
func (m *MockEarlyConnection) RemoteAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoteAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// RemoteAddr indicates an expected call of RemoteAddr.
func (mr *MockEarlyConnectionMockRecorder) RemoteAddr() *EarlyConnectionRemoteAddrCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteAddr", reflect.TypeOf((*MockEarlyConnection)(nil).RemoteAddr))
	return &EarlyConnectionRemoteAddrCall{Call: call}
}

// EarlyConnectionRemoteAddrCall wrap *gomock.Call
type EarlyConnectionRemoteAddrCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionRemoteAddrCall) Return(arg0 net.Addr) *EarlyConnectionRemoteAddrCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionRemoteAddrCall) Do(f func() net.Addr) *EarlyConnectionRemoteAddrCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionRemoteAddrCall) DoAndReturn(f func() net.Addr) *EarlyConnectionRemoteAddrCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SendDatagram mocks base method.
func (m *MockEarlyConnection) SendDatagram(arg0 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendDatagram", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendDatagram indicates an expected call of SendDatagram.
func (mr *MockEarlyConnectionMockRecorder) SendDatagram(arg0 any) *EarlyConnectionSendDatagramCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendDatagram", reflect.TypeOf((*MockEarlyConnection)(nil).SendDatagram), arg0)
	return &EarlyConnectionSendDatagramCall{Call: call}
}

// EarlyConnectionSendDatagramCall wrap *gomock.Call
type EarlyConnectionSendDatagramCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionSendDatagramCall) Return(arg0 error) *EarlyConnectionSendDatagramCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionSendDatagramCall) Do(f func([]byte) error) *EarlyConnectionSendDatagramCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionSendDatagramCall) DoAndReturn(f func([]byte) error) *EarlyConnectionSendDatagramCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetMaxBandwidth mocks base method.
func (m *MockEarlyConnection) SetMaxBandwidth(arg0 uint64) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetMaxBandwidth", arg0)
}

// SetMaxBandwidth indicates an expected call of SetMaxBandwidth.
func (mr *MockEarlyConnectionMockRecorder) SetMaxBandwidth(arg0 any) *EarlyConnectionSetMaxBandwidthCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxBandwidth", reflect.TypeOf((*MockEarlyConnection)(nil).SetMaxBandwidth), arg0)
	return &EarlyConnectionSetMaxBandwidthCall{Call: call}
}

// EarlyConnectionSetMaxBandwidthCall wrap *gomock.Call
type EarlyConnectionSetMaxBandwidthCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *EarlyConnectionSetMaxBandwidthCall) Return() *EarlyConnectionSetMaxBandwidthCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *EarlyConnectionSetMaxBandwidthCall) Do(f func(uint64)) *EarlyConnectionSetMaxBandwidthCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *EarlyConnectionSetMaxBandwidthCall) DoAndReturn(f func(uint64)) *EarlyConnectionSetMaxBandwidthCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
