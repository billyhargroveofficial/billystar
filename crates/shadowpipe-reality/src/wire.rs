//! Minimal big-endian TLS wire writer with length-prefix backpatching.
//!
//! TLS messages are full of nested length-prefixed blocks. `len8`/`len16`/`len24`
//! reserve the length field, run a closure that writes the body, then backpatch
//! the field with the body's actual size — so callers never hand-count lengths.

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u24(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes()[1..]);
    }
    pub fn raw(&mut self, d: &[u8]) {
        self.buf.extend_from_slice(d);
    }
    /// Write a u8-length-prefixed block produced by `f`.
    pub fn len8(&mut self, f: impl FnOnce(&mut Writer)) {
        let p = self.buf.len();
        self.buf.push(0);
        f(self);
        let n = self.buf.len() - p - 1;
        assert!(n <= 0xff, "len8 overflow ({n})");
        self.buf[p] = n as u8;
    }
    /// Write a u16-length-prefixed block produced by `f`.
    pub fn len16(&mut self, f: impl FnOnce(&mut Writer)) {
        let p = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        f(self);
        let n = self.buf.len() - p - 2;
        assert!(n <= 0xffff, "len16 overflow ({n})");
        self.buf[p..p + 2].copy_from_slice(&(n as u16).to_be_bytes());
    }
    /// Write a u24-length-prefixed block produced by `f`.
    pub fn len24(&mut self, f: impl FnOnce(&mut Writer)) {
        let p = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        f(self);
        let n = self.buf.len() - p - 3;
        assert!(n <= 0xff_ffff, "len24 overflow ({n})");
        self.buf[p..p + 3].copy_from_slice(&(n as u32).to_be_bytes()[1..]);
    }
}
