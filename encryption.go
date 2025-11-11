package main

import "errors"

type RC4Cipher struct {
	state     [256]uint32
	initState [256]uint32
	i, j      uint8
}

func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	k := len(key)
	if k < 1 || k > 256 {
		return nil, errors.New("invalid key size for RC4 cipher")
	}
	var c RC4Cipher
	for i := range 256 {
		c.state[i] = uint32(i)
	}
	var j uint8
	for i := range 256 {
		j += uint8(c.state[i]) + key[i%k]
		c.state[i], c.state[j] = c.state[j], c.state[i]
	}
	if copied := copy(c.initState[:], c.state[:]); copied != 256 {
		return nil, errors.New("invalid initial state for RC4 cipher")
	}
	return &c, nil
}

// Resets RC4Cipher to initial state after creation of itself or its parent.
func (c *RC4Cipher) Reset() {
	for i := range 256 {
		c.state[i] = c.initState[i]
	}
	c.i, c.j = 0, 0
}

// XORs src with the keystream.
// We do not check for overlap of dst and src since this should be internal only.
func (c *RC4Cipher) XOR(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	i, j := c.i, c.j
	_ = dst[:len(src)-1]
	dst = dst[:len(src)]
	for k, v := range src {
		i += 1
		x := c.state[i]
		j += uint8(x)
		y := c.state[j]
		c.state[i], c.state[j] = y, x
		dst[k] = v ^ uint8(c.state[uint8(x+y)])
	}
	c.i, c.j = i, j
}

// Performs XORs on the keystream to progress state forward n bytes without storing result.
// This is used to help recover/discover cipher state.
func (c *RC4Cipher) Skip(n uint32) {
	i, j := c.i, c.j
	for range n {
		i += 1
		x := c.state[i]
		j += uint8(x)
		y := c.state[j]
		c.state[i], c.state[j] = y, x
	}
	c.i, c.j = i, j
}

func (c *RC4Cipher) Fork() *RC4Cipher {
	var child RC4Cipher
	copy(child.state[:], c.state[:])
	// Shouldn't need to copy initial state for child.
	// copy(child.initState[:], c.initState[:])
	child.i, child.j = c.i, c.j
	return &child
}
