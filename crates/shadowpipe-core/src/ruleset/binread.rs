//! Cursor-based reader for binary rule-set files (sing-box `.srs`-style).
//! Not wired into the text `.list` pipeline yet.
#![allow(dead_code)]

use anyhow::{Context, Result};
use std::io::{Cursor, Read};

pub struct Reader<'a> {
    inner: Cursor<&'a [u8]>,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            inner: Cursor::new(data),
        }
    }

    pub fn remaining(&self) -> usize {
        (self.inner.get_ref().len() as u64).saturating_sub(self.inner.position()) as usize
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.inner
            .read_exact(&mut b)
            .context("unexpected EOF reading u8")?;
        Ok(b[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let mut b = [0u8; 2];
        self.inner
            .read_exact(&mut b)
            .context("unexpected EOF u16")?;
        Ok(u16::from_be_bytes(b))
    }

    pub fn read_u64_be(&mut self) -> Result<u64> {
        let mut b = [0u8; 8];
        self.inner
            .read_exact(&mut b)
            .context("unexpected EOF u64")?;
        Ok(u64::from_be_bytes(b))
    }

    pub fn read_uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.read_u8()?;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                anyhow::bail!("uvarint overflow");
            }
        }
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        // A length field is attacker-controlled; never pre-allocate more than the
        // bytes that actually remain, or a crafted `n` (e.g. usize::MAX) is an OOM.
        if n > self.remaining() {
            anyhow::bail!(
                "rule-set claims {n} bytes but only {} remain",
                self.remaining()
            );
        }
        let mut buf = vec![0u8; n];
        self.inner
            .read_exact(&mut buf)
            .context("unexpected EOF reading bytes")?;
        Ok(buf)
    }

    pub fn read_string(&mut self) -> Result<String> {
        let len = self.read_uvarint()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes).context("invalid utf8 string in rule-set")
    }

    pub fn read_string_list(&mut self) -> Result<Vec<String>> {
        let count = self.read_uvarint()? as usize;
        // Each element costs >= 1 byte, so the count can't exceed what's left:
        // cap the pre-allocation by `remaining()` so a bogus count isn't an OOM.
        let mut out = Vec::with_capacity(count.min(self.remaining()));
        for _ in 0..count {
            out.push(self.read_string()?);
        }
        Ok(out)
    }

    pub fn read_u16_list(&mut self) -> Result<Vec<u16>> {
        let count = self.read_uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(self.remaining()));
        for _ in 0..count {
            out.push(self.read_u16_be()?);
        }
        Ok(out)
    }

    pub fn read_u64_list(&mut self) -> Result<Vec<u64>> {
        let count = self.read_uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(self.remaining()));
        for _ in 0..count {
            out.push(self.read_u64_be()?);
        }
        Ok(out)
    }

    pub fn read_byte_slice(&mut self) -> Result<Vec<u8>> {
        let len = self.read_uvarint()? as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        self.read_bytes(len)
    }
}
