package netfilter

import (
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// SetReadBuffer updates the buffer size of the connection or
// returns an error.
func (c *Conn) SetReadBuffer(bufSize int) error {
	return c.conn.SetReadBuffer(bufSize)
}

// SetReadBufferForce updates the buffer size of the connection or
// returns an error.
func (c *Conn) SetReadBufferForce(bufSize int) error {
	return c.conn.SetReadBufferForce(bufSize)
}

func (h *Header) Unmarshal(nlm netlink.Message) error {
	return h.unmarshal(nlm)
}

func (a *Attribute) UnmarshalNested() error {
	// Unmarshal recursively if the netlink Nested flag is set
	if a.Nested {
		var err error
		if a.Children, err = unmarshalAttributes(a.Data); err != nil {
			return err
		}
	}
	return nil
}

// WalkMessage unmarshals a netlink.Message into a Netfilter Header and Attributes.
func WalkMessage(msg netlink.Message, hdrFn func(Header) (bool, error), attrFn func(Attribute) (bool, error)) (bool, error) {
	var h Header
	err := h.unmarshal(msg)
	if err != nil {
		return false, err
	}
	ok, err := hdrFn(h)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return WalkAttributes(msg.Data[nfHeaderLen:], attrFn)
}

// WalkAttributes steps through a net link message, invoking fn
// once per Attribute structure.
func WalkAttributes(b []byte, fn func(Attribute) (bool, error)) (bool, error) {
	// Obtain a list of parsed netlink attributes possibly holding
	// nested Netfilter attributes in their binary Data field.
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return false, errors.Wrap(err, errWrapNetlinkUnmarshalAttrs)
	}

	for _, nla := range attrs {
		// Copy the netlink attribute's fields into the netfilter attribute.
		nfa := Attribute{
			// Only consider the rightmost 14 bits for Type
			Type: nla.Type & ^(uint16(unix.NLA_F_NESTED) | uint16(unix.NLA_F_NET_BYTEORDER)),
			Data: nla.Data,
		}

		// Boolean flags extracted from the two leftmost bits of Type
		nfa.Nested = (nla.Type & uint16(unix.NLA_F_NESTED)) != 0
		nfa.NetByteOrder = (nla.Type & uint16(unix.NLA_F_NET_BYTEORDER)) != 0

		if nfa.NetByteOrder && nfa.Nested {
			return false, errInvalidAttributeFlags
		}

		ok, err := fn(nfa)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	return true, nil
}
