#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(unreachable_code)]

#[allow(unused_imports)]
use binschema_runtime::{BitStreamEncoder, BitStreamDecoder, Endianness, BitOrder, Result, BinSchemaError, EncodeContext, FieldValue};
#[allow(unused_imports)]
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct OpExecInput {
    pub argv: Vec<std::string::String>,
    pub env_keys: Vec<std::string::String>,
    pub env_values: Vec<std::string::String>,
    pub cwd: std::string::String,
    pub stdin: Vec<u8>,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpExecOutput {
    pub kind: u8,
    pub argv: Vec<std::string::String>,
    pub env_keys: Vec<std::string::String>,
    pub env_values: Vec<std::string::String>,
    pub cwd: std::string::String,
    pub stdin: Vec<u8>,
    pub timeout_ms: u32,
}

pub type OpExec = OpExecOutput;

impl OpExecInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(0);
        encoder.write_u16_le(self.argv.len() as u16);
        for item in &self.argv {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.env_keys.len() as u16);
        for item in &self.env_keys {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.env_values.len() as u16);
        for item in &self.env_values {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.cwd.len() as u16);
        let string_bytes: &[u8] = self.cwd.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.stdin.len() as u32);
        for item in &self.stdin {
            encoder.write_byte(*item);
        }
        encoder.write_u32_le(self.timeout_ms);
        Ok(())
    }

}

impl OpExecOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 0u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let mut argv = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            argv.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let mut env_keys = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            env_keys.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let mut env_values = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            env_values.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let cwd = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u32_le()? as usize;
        let mut stdin = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            stdin.push(item);
        }
        let timeout_ms = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            argv,
            env_keys,
            env_values,
            cwd,
            stdin,
            timeout_ms,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpExecInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpExecInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpExecOutput> for OpExecInput {
    fn from(o: OpExecOutput) -> Self {
        Self {
            argv: o.argv,
            env_keys: o.env_keys,
            env_values: o.env_values,
            cwd: o.cwd,
            stdin: o.stdin,
            timeout_ms: o.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpShellInput {
    pub command: std::string::String,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpShellOutput {
    pub kind: u8,
    pub command: std::string::String,
    pub timeout_ms: u32,
}

pub type OpShell = OpShellOutput;

impl OpShellInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(1);
        encoder.write_u16_le(self.command.len() as u16);
        let string_bytes: &[u8] = self.command.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.timeout_ms);
        Ok(())
    }

}

impl OpShellOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 1u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let command = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let timeout_ms = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            command,
            timeout_ms,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpShellInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpShellInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpShellOutput> for OpShellInput {
    fn from(o: OpShellOutput) -> Self {
        Self {
            command: o.command,
            timeout_ms: o.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpWriteFileInput {
    pub path: std::string::String,
    pub mode: u32,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpWriteFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub mode: u32,
    pub content: Vec<u8>,
}

pub type OpWriteFile = OpWriteFileOutput;

impl OpWriteFileInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(2);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.mode);
        encoder.write_u32_le(self.content.len() as u32);
        for item in &self.content {
            encoder.write_byte(*item);
        }
        Ok(())
    }

}

impl OpWriteFileOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 2u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let mode = decoder.read_u32_le()?;
        let length = decoder.read_u32_le()? as usize;
        let mut content = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            content.push(item);
        }
        Ok(Self {
            kind,
            path,
            mode,
            content,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpWriteFileInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpWriteFileInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpWriteFileOutput> for OpWriteFileInput {
    fn from(o: OpWriteFileOutput) -> Self {
        Self {
            path: o.path,
            mode: o.mode,
            content: o.content,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGatherFactsInput {
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGatherFactsOutput {
    pub kind: u8,
}

pub type OpGatherFacts = OpGatherFactsOutput;

impl OpGatherFactsInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(3);
        Ok(())
    }

}

impl OpGatherFactsOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 3u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        Ok(Self {
            kind,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpGatherFactsInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpGatherFactsInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpGatherFactsOutput> for OpGatherFactsInput {
    fn from(_o: OpGatherFactsOutput) -> Self {
        Self {
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpStatInput {
    pub path: std::string::String,
    pub follow: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpStatOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub follow: u8,
}

pub type OpStat = OpStatOutput;

impl OpStatInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(4);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.follow);
        Ok(())
    }

}

impl OpStatOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 4u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let follow = decoder.read_byte()?;
        Ok(Self {
            kind,
            path,
            follow,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpStatInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpStatInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpStatOutput> for OpStatInput {
    fn from(o: OpStatOutput) -> Self {
        Self {
            path: o.path,
            follow: o.follow,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpWaitForInput {
    pub host: std::string::String,
    pub port: u32,
    pub path: std::string::String,
    pub state: u8,
    pub timeout_ms: u32,
    pub delay_ms: u32,
    pub sleep_ms: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpWaitForOutput {
    pub kind: u8,
    pub host: std::string::String,
    pub port: u32,
    pub path: std::string::String,
    pub state: u8,
    pub timeout_ms: u32,
    pub delay_ms: u32,
    pub sleep_ms: u32,
}

pub type OpWaitFor = OpWaitForOutput;

impl OpWaitForInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(6);
        encoder.write_u16_le(self.host.len() as u16);
        let string_bytes: &[u8] = self.host.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.port);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_u32_le(self.timeout_ms);
        encoder.write_u32_le(self.delay_ms);
        encoder.write_u32_le(self.sleep_ms);
        Ok(())
    }

}

impl OpWaitForOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 6u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let host = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let port = decoder.read_u32_le()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let timeout_ms = decoder.read_u32_le()?;
        let delay_ms = decoder.read_u32_le()?;
        let sleep_ms = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            host,
            port,
            path,
            state,
            timeout_ms,
            delay_ms,
            sleep_ms,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpWaitForInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpWaitForInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpWaitForOutput> for OpWaitForInput {
    fn from(o: OpWaitForOutput) -> Self {
        Self {
            host: o.host,
            port: o.port,
            path: o.path,
            state: o.state,
            timeout_ms: o.timeout_ms,
            delay_ms: o.delay_ms,
            sleep_ms: o.sleep_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpFileInput {
    pub path: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub recurse: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub recurse: u8,
}

pub type OpFile = OpFileOutput;

impl OpFileInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(5);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.has_mode);
        encoder.write_u32_le(self.mode);
        encoder.write_u16_le(self.owner.len() as u16);
        let string_bytes: &[u8] = self.owner.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.group.len() as u16);
        let string_bytes: &[u8] = self.group.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.recurse);
        Ok(())
    }

}

impl OpFileOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 5u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let has_mode = decoder.read_byte()?;
        let mode = decoder.read_u32_le()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let owner = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let group = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let recurse = decoder.read_byte()?;
        Ok(Self {
            kind,
            path,
            state,
            has_mode,
            mode,
            owner,
            group,
            recurse,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpFileInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpFileInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpFileOutput> for OpFileInput {
    fn from(o: OpFileOutput) -> Self {
        Self {
            path: o.path,
            state: o.state,
            has_mode: o.has_mode,
            mode: o.mode,
            owner: o.owner,
            group: o.group,
            recurse: o.recurse,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpLineInFileInput {
    pub path: std::string::String,
    pub regexp: std::string::String,
    pub line: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub create: u8,
    pub insertbefore: std::string::String,
    pub insertafter: std::string::String,
    pub backrefs: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpLineInFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub regexp: std::string::String,
    pub line: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub create: u8,
    pub insertbefore: std::string::String,
    pub insertafter: std::string::String,
    pub backrefs: u8,
}

pub type OpLineInFile = OpLineInFileOutput;

impl OpLineInFileInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(7);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.regexp.len() as u16);
        let string_bytes: &[u8] = self.regexp.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.line.len() as u32);
        let string_bytes: &[u8] = self.line.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.has_mode);
        encoder.write_u32_le(self.mode);
        encoder.write_byte(self.create);
        encoder.write_u16_le(self.insertbefore.len() as u16);
        let string_bytes: &[u8] = self.insertbefore.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.insertafter.len() as u16);
        let string_bytes: &[u8] = self.insertafter.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.backrefs);
        Ok(())
    }

}

impl OpLineInFileOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 7u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let regexp = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u32_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let line = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let has_mode = decoder.read_byte()?;
        let mode = decoder.read_u32_le()?;
        let create = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let insertbefore = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let insertafter = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let backrefs = decoder.read_byte()?;
        Ok(Self {
            kind,
            path,
            regexp,
            line,
            state,
            has_mode,
            mode,
            create,
            insertbefore,
            insertafter,
            backrefs,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpLineInFileInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpLineInFileInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpLineInFileOutput> for OpLineInFileInput {
    fn from(o: OpLineInFileOutput) -> Self {
        Self {
            path: o.path,
            regexp: o.regexp,
            line: o.line,
            state: o.state,
            has_mode: o.has_mode,
            mode: o.mode,
            create: o.create,
            insertbefore: o.insertbefore,
            insertafter: o.insertafter,
            backrefs: o.backrefs,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpBlockInFileInput {
    pub path: std::string::String,
    pub block: std::string::String,
    pub marker: std::string::String,
    pub marker_begin: std::string::String,
    pub marker_end: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub create: u8,
    pub insertbefore: std::string::String,
    pub insertafter: std::string::String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpBlockInFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub block: std::string::String,
    pub marker: std::string::String,
    pub marker_begin: std::string::String,
    pub marker_end: std::string::String,
    pub state: u8,
    pub has_mode: u8,
    pub mode: u32,
    pub create: u8,
    pub insertbefore: std::string::String,
    pub insertafter: std::string::String,
}

pub type OpBlockInFile = OpBlockInFileOutput;

impl OpBlockInFileInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(8);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.block.len() as u32);
        let string_bytes: &[u8] = self.block.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.marker.len() as u16);
        let string_bytes: &[u8] = self.marker.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.marker_begin.len() as u16);
        let string_bytes: &[u8] = self.marker_begin.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.marker_end.len() as u16);
        let string_bytes: &[u8] = self.marker_end.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.has_mode);
        encoder.write_u32_le(self.mode);
        encoder.write_byte(self.create);
        encoder.write_u16_le(self.insertbefore.len() as u16);
        let string_bytes: &[u8] = self.insertbefore.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.insertafter.len() as u16);
        let string_bytes: &[u8] = self.insertafter.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        Ok(())
    }

}

impl OpBlockInFileOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 8u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u32_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let block = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let marker = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let marker_begin = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let marker_end = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let has_mode = decoder.read_byte()?;
        let mode = decoder.read_u32_le()?;
        let create = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let insertbefore = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let insertafter = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        Ok(Self {
            kind,
            path,
            block,
            marker,
            marker_begin,
            marker_end,
            state,
            has_mode,
            mode,
            create,
            insertbefore,
            insertafter,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpBlockInFileInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpBlockInFileInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpBlockInFileOutput> for OpBlockInFileInput {
    fn from(o: OpBlockInFileOutput) -> Self {
        Self {
            path: o.path,
            block: o.block,
            marker: o.marker,
            marker_begin: o.marker_begin,
            marker_end: o.marker_end,
            state: o.state,
            has_mode: o.has_mode,
            mode: o.mode,
            create: o.create,
            insertbefore: o.insertbefore,
            insertafter: o.insertafter,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPackageInput {
    pub manager: u8,
    pub names: Vec<std::string::String>,
    pub state: u8,
    pub update_cache: u8,
    pub cache_valid_time: u32,
    pub purge: u8,
    pub autoremove: u8,
    pub default_release: std::string::String,
    pub allow_unauthenticated: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPackageOutput {
    pub kind: u8,
    pub manager: u8,
    pub names: Vec<std::string::String>,
    pub state: u8,
    pub update_cache: u8,
    pub cache_valid_time: u32,
    pub purge: u8,
    pub autoremove: u8,
    pub default_release: std::string::String,
    pub allow_unauthenticated: u8,
}

pub type OpPackage = OpPackageOutput;

impl OpPackageInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(10);
        encoder.write_byte(self.manager);
        encoder.write_u16_le(self.names.len() as u16);
        for item in &self.names {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.update_cache);
        encoder.write_u32_le(self.cache_valid_time);
        encoder.write_byte(self.purge);
        encoder.write_byte(self.autoremove);
        encoder.write_u16_le(self.default_release.len() as u16);
        let string_bytes: &[u8] = self.default_release.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.allow_unauthenticated);
        Ok(())
    }

}

impl OpPackageOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 10u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let manager = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let mut names = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            names.push(item);
        }
        let state = decoder.read_byte()?;
        let update_cache = decoder.read_byte()?;
        let cache_valid_time = decoder.read_u32_le()?;
        let purge = decoder.read_byte()?;
        let autoremove = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let default_release = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let allow_unauthenticated = decoder.read_byte()?;
        Ok(Self {
            kind,
            manager,
            names,
            state,
            update_cache,
            cache_valid_time,
            purge,
            autoremove,
            default_release,
            allow_unauthenticated,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpPackageInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpPackageInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpPackageOutput> for OpPackageInput {
    fn from(o: OpPackageOutput) -> Self {
        Self {
            manager: o.manager,
            names: o.names,
            state: o.state,
            update_cache: o.update_cache,
            cache_valid_time: o.cache_valid_time,
            purge: o.purge,
            autoremove: o.autoremove,
            default_release: o.default_release,
            allow_unauthenticated: o.allow_unauthenticated,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpSystemdInput {
    pub name: std::string::String,
    pub state: u8,
    pub has_enabled: u8,
    pub enabled: u8,
    pub has_masked: u8,
    pub masked: u8,
    pub daemon_reload: u8,
    pub no_block: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpSystemdOutput {
    pub kind: u8,
    pub name: std::string::String,
    pub state: u8,
    pub has_enabled: u8,
    pub enabled: u8,
    pub has_masked: u8,
    pub masked: u8,
    pub daemon_reload: u8,
    pub no_block: u8,
}

pub type OpSystemd = OpSystemdOutput;

impl OpSystemdInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(9);
        encoder.write_u16_le(self.name.len() as u16);
        let string_bytes: &[u8] = self.name.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.has_enabled);
        encoder.write_byte(self.enabled);
        encoder.write_byte(self.has_masked);
        encoder.write_byte(self.masked);
        encoder.write_byte(self.daemon_reload);
        encoder.write_byte(self.no_block);
        Ok(())
    }

}

impl OpSystemdOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 9u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let name = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let has_enabled = decoder.read_byte()?;
        let enabled = decoder.read_byte()?;
        let has_masked = decoder.read_byte()?;
        let masked = decoder.read_byte()?;
        let daemon_reload = decoder.read_byte()?;
        let no_block = decoder.read_byte()?;
        Ok(Self {
            kind,
            name,
            state,
            has_enabled,
            enabled,
            has_masked,
            masked,
            daemon_reload,
            no_block,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpSystemdInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpSystemdInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpSystemdOutput> for OpSystemdInput {
    fn from(o: OpSystemdOutput) -> Self {
        Self {
            name: o.name,
            state: o.state,
            has_enabled: o.has_enabled,
            enabled: o.enabled,
            has_masked: o.has_masked,
            masked: o.masked,
            daemon_reload: o.daemon_reload,
            no_block: o.no_block,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUfwInput {
    pub op: u8,
    pub rule: std::string::String,
    pub direction: std::string::String,
    pub proto: std::string::String,
    pub from_ip: std::string::String,
    pub from_port: std::string::String,
    pub to_ip: std::string::String,
    pub to_port: std::string::String,
    pub interface: std::string::String,
    pub comment: std::string::String,
    pub delete: u8,
    pub insert: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUfwOutput {
    pub kind: u8,
    pub op: u8,
    pub rule: std::string::String,
    pub direction: std::string::String,
    pub proto: std::string::String,
    pub from_ip: std::string::String,
    pub from_port: std::string::String,
    pub to_ip: std::string::String,
    pub to_port: std::string::String,
    pub interface: std::string::String,
    pub comment: std::string::String,
    pub delete: u8,
    pub insert: u32,
}

pub type OpUfw = OpUfwOutput;

impl OpUfwInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(11);
        encoder.write_byte(self.op);
        encoder.write_u16_le(self.rule.len() as u16);
        let string_bytes: &[u8] = self.rule.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.direction.len() as u16);
        let string_bytes: &[u8] = self.direction.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.proto.len() as u16);
        let string_bytes: &[u8] = self.proto.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.from_ip.len() as u16);
        let string_bytes: &[u8] = self.from_ip.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.from_port.len() as u16);
        let string_bytes: &[u8] = self.from_port.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.to_ip.len() as u16);
        let string_bytes: &[u8] = self.to_ip.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.to_port.len() as u16);
        let string_bytes: &[u8] = self.to_port.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.interface.len() as u16);
        let string_bytes: &[u8] = self.interface.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.comment.len() as u16);
        let string_bytes: &[u8] = self.comment.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.delete);
        encoder.write_u32_le(self.insert);
        Ok(())
    }

}

impl OpUfwOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 11u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let op = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let rule = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let direction = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let proto = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let from_ip = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let from_port = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let to_ip = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let to_port = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let interface = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let comment = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let delete = decoder.read_byte()?;
        let insert = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            op,
            rule,
            direction,
            proto,
            from_ip,
            from_port,
            to_ip,
            to_port,
            interface,
            comment,
            delete,
            insert,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpUfwInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpUfwInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpUfwOutput> for OpUfwInput {
    fn from(o: OpUfwOutput) -> Self {
        Self {
            op: o.op,
            rule: o.rule,
            direction: o.direction,
            proto: o.proto,
            from_ip: o.from_ip,
            from_port: o.from_port,
            to_ip: o.to_ip,
            to_port: o.to_port,
            interface: o.interface,
            comment: o.comment,
            delete: o.delete,
            insert: o.insert,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    OpExec(OpExecOutput),
    OpShell(OpShellOutput),
    OpWriteFile(OpWriteFileOutput),
    OpGatherFacts(OpGatherFactsOutput),
    OpStat(OpStatOutput),
    OpFile(OpFileOutput),
    OpWaitFor(OpWaitForOutput),
    OpLineInFile(OpLineInFileOutput),
    OpBlockInFile(OpBlockInFileOutput),
    OpSystemd(OpSystemdOutput),
    OpPackage(OpPackageOutput),
    OpUfw(OpUfwOutput),
}

impl Op {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        match self {
            Op::OpExec(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.argv.len() as u16, Endianness::LittleEndian);
                for item in &v.argv {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.env_keys.len() as u16, Endianness::LittleEndian);
                for item in &v.env_keys {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.env_values.len() as u16, Endianness::LittleEndian);
                for item in &v.env_values {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.cwd.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.cwd.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.stdin.len() as u32, Endianness::LittleEndian);
                for item in &v.stdin {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
            }
            Op::OpShell(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.command.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.command.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
            }
            Op::OpWriteFile(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.mode, Endianness::LittleEndian);
                encoder.write_uint32(v.content.len() as u32, Endianness::LittleEndian);
                for item in &v.content {
                    encoder.write_uint8(*item);
                }
            }
            Op::OpGatherFacts(v) => {
                encoder.write_uint8(v.kind);
            }
            Op::OpStat(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.follow);
            }
            Op::OpFile(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.has_mode);
                encoder.write_uint32(v.mode, Endianness::LittleEndian);
                encoder.write_uint16(v.owner.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.owner.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.group.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.group.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.recurse);
            }
            Op::OpWaitFor(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.host.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.host.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.port, Endianness::LittleEndian);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
                encoder.write_uint32(v.delay_ms, Endianness::LittleEndian);
                encoder.write_uint32(v.sleep_ms, Endianness::LittleEndian);
            }
            Op::OpLineInFile(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.regexp.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.regexp.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.line.len() as u32, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.line.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.has_mode);
                encoder.write_uint32(v.mode, Endianness::LittleEndian);
                encoder.write_uint8(v.create);
                encoder.write_uint16(v.insertbefore.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.insertbefore.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.insertafter.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.insertafter.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.backrefs);
            }
            Op::OpBlockInFile(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.block.len() as u32, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.block.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.marker.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.marker.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.marker_begin.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.marker_begin.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.marker_end.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.marker_end.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.has_mode);
                encoder.write_uint32(v.mode, Endianness::LittleEndian);
                encoder.write_uint8(v.create);
                encoder.write_uint16(v.insertbefore.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.insertbefore.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.insertafter.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.insertafter.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
            }
            Op::OpSystemd(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.name.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.name.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.has_enabled);
                encoder.write_uint8(v.enabled);
                encoder.write_uint8(v.has_masked);
                encoder.write_uint8(v.masked);
                encoder.write_uint8(v.daemon_reload);
                encoder.write_uint8(v.no_block);
            }
            Op::OpPackage(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint8(v.manager);
                encoder.write_uint16(v.names.len() as u16, Endianness::LittleEndian);
                for item in &v.names {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.update_cache);
                encoder.write_uint32(v.cache_valid_time, Endianness::LittleEndian);
                encoder.write_uint8(v.purge);
                encoder.write_uint8(v.autoremove);
                encoder.write_uint16(v.default_release.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.default_release.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.allow_unauthenticated);
            }
            Op::OpUfw(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint8(v.op);
                encoder.write_uint16(v.rule.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.rule.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.direction.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.direction.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.proto.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.proto.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.from_ip.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.from_ip.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.from_port.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.from_port.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.to_ip.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.to_ip.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.to_port.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.to_port.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.interface.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.interface.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.comment.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.comment.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.delete);
                encoder.write_uint32(v.insert, Endianness::LittleEndian);
            }
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let value = decoder.peek_uint8()?;
        // Match on discriminator value
        if value == 0 {
            Ok(Op::OpExec(OpExecOutput::decode_with_decoder(decoder)?))
        } else if value == 1 {
            Ok(Op::OpShell(OpShellOutput::decode_with_decoder(decoder)?))
        } else if value == 2 {
            Ok(Op::OpWriteFile(OpWriteFileOutput::decode_with_decoder(decoder)?))
        } else if value == 3 {
            Ok(Op::OpGatherFacts(OpGatherFactsOutput::decode_with_decoder(decoder)?))
        } else if value == 4 {
            Ok(Op::OpStat(OpStatOutput::decode_with_decoder(decoder)?))
        } else if value == 5 {
            Ok(Op::OpFile(OpFileOutput::decode_with_decoder(decoder)?))
        } else if value == 6 {
            Ok(Op::OpWaitFor(OpWaitForOutput::decode_with_decoder(decoder)?))
        } else if value == 7 {
            Ok(Op::OpLineInFile(OpLineInFileOutput::decode_with_decoder(decoder)?))
        } else if value == 8 {
            Ok(Op::OpBlockInFile(OpBlockInFileOutput::decode_with_decoder(decoder)?))
        } else if value == 9 {
            Ok(Op::OpSystemd(OpSystemdOutput::decode_with_decoder(decoder)?))
        } else if value == 10 {
            Ok(Op::OpPackage(OpPackageOutput::decode_with_decoder(decoder)?))
        } else if value == 11 {
            Ok(Op::OpUfw(OpUfwOutput::decode_with_decoder(decoder)?))
        } else {
            Err(binschema_runtime::BinSchemaError::InvalidVariant(value as u64))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloInput {
    pub arch: u8,
    pub os: u8,
    pub kernel: std::string::String,
    pub hostname: std::string::String,
    pub uid: u32,
    pub gid: u32,
    pub agent_version: std::string::String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloOutput {
    pub kind: u8,
    pub arch: u8,
    pub os: u8,
    pub kernel: std::string::String,
    pub hostname: std::string::String,
    pub uid: u32,
    pub gid: u32,
    pub agent_version: std::string::String,
}

pub type Hello = HelloOutput;

impl HelloInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(0);
        encoder.write_byte(self.arch);
        encoder.write_byte(self.os);
        encoder.write_u16_le(self.kernel.len() as u16);
        let string_bytes: &[u8] = self.kernel.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.hostname.len() as u16);
        let string_bytes: &[u8] = self.hostname.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.uid);
        encoder.write_u32_le(self.gid);
        encoder.write_u16_le(self.agent_version.len() as u16);
        let string_bytes: &[u8] = self.agent_version.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        Ok(())
    }

}

impl HelloOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 0u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let arch = decoder.read_byte()?;
        let os = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let kernel = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let hostname = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let uid = decoder.read_u32_le()?;
        let gid = decoder.read_u32_le()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let agent_version = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        Ok(Self {
            kind,
            arch,
            os,
            kernel,
            hostname,
            uid,
            gid,
            agent_version,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        HelloInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        HelloInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<HelloOutput> for HelloInput {
    fn from(o: HelloOutput) -> Self {
        Self {
            arch: o.arch,
            os: o.os,
            kernel: o.kernel,
            hostname: o.hostname,
            uid: o.uid,
            gid: o.gid,
            agent_version: o.agent_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDispatchInput {
    pub seq: u32,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDispatchOutput {
    pub kind: u8,
    pub seq: u32,
    pub op: Op,
}

pub type TaskDispatch = TaskDispatchOutput;

impl TaskDispatchInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(1);
        encoder.write_u32_le(self.seq);
        self.op.encode_into(encoder)?;
        Ok(())
    }

}

impl TaskDispatchOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 1u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let seq = decoder.read_u32_le()?;
        let op = Op::decode_with_decoder(decoder)?;
        Ok(Self {
            kind,
            seq,
            op,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        TaskDispatchInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        TaskDispatchInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<TaskDispatchOutput> for TaskDispatchInput {
    fn from(o: TaskDispatchOutput) -> Self {
        Self {
            seq: o.seq,
            op: o.op,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskProgressInput {
    pub seq: u32,
    pub stream: u8,
    pub chunk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskProgressOutput {
    pub kind: u8,
    pub seq: u32,
    pub stream: u8,
    pub chunk: Vec<u8>,
}

pub type TaskProgress = TaskProgressOutput;

impl TaskProgressInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(2);
        encoder.write_u32_le(self.seq);
        encoder.write_byte(self.stream);
        encoder.write_u32_le(self.chunk.len() as u32);
        for item in &self.chunk {
            encoder.write_byte(*item);
        }
        Ok(())
    }

}

impl TaskProgressOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 2u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let seq = decoder.read_u32_le()?;
        let stream = decoder.read_byte()?;
        let length = decoder.read_u32_le()? as usize;
        let mut chunk = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            chunk.push(item);
        }
        Ok(Self {
            kind,
            seq,
            stream,
            chunk,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        TaskProgressInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        TaskProgressInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<TaskProgressOutput> for TaskProgressInput {
    fn from(o: TaskProgressOutput) -> Self {
        Self {
            seq: o.seq,
            stream: o.stream,
            chunk: o.chunk,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDoneInput {
    pub seq: u32,
    pub exit_code: i32,
    pub changed: u8,
    pub started_unix_ns: u64,
    pub finished_unix_ns: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDoneOutput {
    pub kind: u8,
    pub seq: u32,
    pub exit_code: i32,
    pub changed: u8,
    pub started_unix_ns: u64,
    pub finished_unix_ns: u64,
}

pub type TaskDone = TaskDoneOutput;

impl TaskDoneInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(3);
        encoder.write_u32_le(self.seq);
        encoder.write_u32_le(self.exit_code as u32);
        encoder.write_byte(self.changed);
        encoder.write_u64_le(self.started_unix_ns);
        encoder.write_u64_le(self.finished_unix_ns);
        Ok(())
    }

}

impl TaskDoneOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 3u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let seq = decoder.read_u32_le()?;
        let exit_code = decoder.read_u32_le()? as i32;
        let changed = decoder.read_byte()?;
        let started_unix_ns = decoder.read_u64_le()?;
        let finished_unix_ns = decoder.read_u64_le()?;
        Ok(Self {
            kind,
            seq,
            exit_code,
            changed,
            started_unix_ns,
            finished_unix_ns,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        TaskDoneInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        TaskDoneInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<TaskDoneOutput> for TaskDoneInput {
    fn from(o: TaskDoneOutput) -> Self {
        Self {
            seq: o.seq,
            exit_code: o.exit_code,
            changed: o.changed,
            started_unix_ns: o.started_unix_ns,
            finished_unix_ns: o.finished_unix_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskErrorInput {
    pub seq: u32,
    pub code: u8,
    pub message: std::string::String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskErrorOutput {
    pub kind: u8,
    pub seq: u32,
    pub code: u8,
    pub message: std::string::String,
}

pub type TaskError = TaskErrorOutput;

impl TaskErrorInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(4);
        encoder.write_u32_le(self.seq);
        encoder.write_byte(self.code);
        encoder.write_u16_le(self.message.len() as u16);
        let string_bytes: &[u8] = self.message.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        Ok(())
    }

}

impl TaskErrorOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 4u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let seq = decoder.read_u32_le()?;
        let code = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let message = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        Ok(Self {
            kind,
            seq,
            code,
            message,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        TaskErrorInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        TaskErrorInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<TaskErrorOutput> for TaskErrorInput {
    fn from(o: TaskErrorOutput) -> Self {
        Self {
            seq: o.seq,
            code: o.code,
            message: o.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ByeInput {
}

#[derive(Debug, Clone, PartialEq)]
pub struct ByeOutput {
    pub kind: u8,
}

pub type Bye = ByeOutput;

impl ByeInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(5);
        Ok(())
    }

}

impl ByeOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 5u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        Ok(Self {
            kind,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ByeInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        ByeInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<ByeOutput> for ByeInput {
    fn from(_o: ByeOutput) -> Self {
        Self {
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PingInput {
}

#[derive(Debug, Clone, PartialEq)]
pub struct PingOutput {
    pub kind: u8,
}

pub type Ping = PingOutput;

impl PingInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(6);
        Ok(())
    }

}

impl PingOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 6u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        Ok(Self {
            kind,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        PingInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        PingInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<PingOutput> for PingInput {
    fn from(_o: PingOutput) -> Self {
        Self {
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PongInput {
    pub agent_recv_unix_ns: u64,
    pub agent_sent_unix_ns: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PongOutput {
    pub kind: u8,
    pub agent_recv_unix_ns: u64,
    pub agent_sent_unix_ns: u64,
}

pub type Pong = PongOutput;

impl PongInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(7);
        encoder.write_u64_le(self.agent_recv_unix_ns);
        encoder.write_u64_le(self.agent_sent_unix_ns);
        Ok(())
    }

}

impl PongOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 7u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(kind as u64));
        }
        let agent_recv_unix_ns = decoder.read_u64_le()?;
        let agent_sent_unix_ns = decoder.read_u64_le()?;
        Ok(Self {
            kind,
            agent_recv_unix_ns,
            agent_sent_unix_ns,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        PongInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        PongInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<PongOutput> for PongInput {
    fn from(o: PongOutput) -> Self {
        Self {
            agent_recv_unix_ns: o.agent_recv_unix_ns,
            agent_sent_unix_ns: o.agent_sent_unix_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Hello(HelloOutput),
    TaskDispatch(TaskDispatchOutput),
    TaskProgress(TaskProgressOutput),
    TaskDone(TaskDoneOutput),
    TaskError(TaskErrorOutput),
    Bye(ByeOutput),
    Ping(PingOutput),
    Pong(PongOutput),
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        match self {
            Message::Hello(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint8(v.arch);
                encoder.write_uint8(v.os);
                encoder.write_uint16(v.kernel.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.kernel.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.hostname.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.hostname.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.uid, Endianness::LittleEndian);
                encoder.write_uint32(v.gid, Endianness::LittleEndian);
                encoder.write_uint16(v.agent_version.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.agent_version.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
            }
            Message::TaskDispatch(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.seq, Endianness::LittleEndian);
                v.op.encode_into(encoder)?;
            }
            Message::TaskProgress(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.seq, Endianness::LittleEndian);
                encoder.write_uint8(v.stream);
                encoder.write_uint32(v.chunk.len() as u32, Endianness::LittleEndian);
                for item in &v.chunk {
                    encoder.write_uint8(*item);
                }
            }
            Message::TaskDone(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.seq, Endianness::LittleEndian);
                encoder.write_int32(v.exit_code, Endianness::LittleEndian);
                encoder.write_uint8(v.changed);
                encoder.write_uint64(v.started_unix_ns, Endianness::LittleEndian);
                encoder.write_uint64(v.finished_unix_ns, Endianness::LittleEndian);
            }
            Message::TaskError(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.seq, Endianness::LittleEndian);
                encoder.write_uint8(v.code);
                encoder.write_uint16(v.message.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.message.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
            }
            Message::Bye(v) => {
                encoder.write_uint8(v.kind);
            }
            Message::Ping(v) => {
                encoder.write_uint8(v.kind);
            }
            Message::Pong(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint64(v.agent_recv_unix_ns, Endianness::LittleEndian);
                encoder.write_uint64(v.agent_sent_unix_ns, Endianness::LittleEndian);
            }
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let value = decoder.peek_uint8()?;
        // Match on discriminator value
        if value == 0 {
            Ok(Message::Hello(HelloOutput::decode_with_decoder(decoder)?))
        } else if value == 1 {
            Ok(Message::TaskDispatch(TaskDispatchOutput::decode_with_decoder(decoder)?))
        } else if value == 2 {
            Ok(Message::TaskProgress(TaskProgressOutput::decode_with_decoder(decoder)?))
        } else if value == 3 {
            Ok(Message::TaskDone(TaskDoneOutput::decode_with_decoder(decoder)?))
        } else if value == 4 {
            Ok(Message::TaskError(TaskErrorOutput::decode_with_decoder(decoder)?))
        } else if value == 5 {
            Ok(Message::Bye(ByeOutput::decode_with_decoder(decoder)?))
        } else if value == 6 {
            Ok(Message::Ping(PingOutput::decode_with_decoder(decoder)?))
        } else if value == 7 {
            Ok(Message::Pong(PongOutput::decode_with_decoder(decoder)?))
        } else {
            Err(binschema_runtime::BinSchemaError::InvalidVariant(value as u64))
        }
    }
}
