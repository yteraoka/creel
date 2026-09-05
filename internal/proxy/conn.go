package proxy

import (
	"net"
	"sync"
)

// singleConnListener hands one already-accepted connection to an http.Server
// and then blocks until that connection closes, so Serve returns when the
// client is done.
type singleConnListener struct {
	conn chan net.Conn
	done chan struct{}
	addr net.Addr
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	ln := &singleConnListener{
		conn: make(chan net.Conn, 1),
		done: make(chan struct{}),
		addr: c.LocalAddr(),
	}
	ln.conn <- &notifyConn{Conn: c, closed: ln.done}
	close(ln.conn)
	return ln
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if c, ok := <-l.conn; ok {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.addr }

// notifyConn closes a channel once the connection is closed.
type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

// prefixConn replays bytes that were buffered out of the connection before it
// was hijacked.
type prefixConn struct {
	net.Conn
	pending []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
