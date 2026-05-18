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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 0, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 1, got {}", kind)));
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
    pub only_if_missing: u8,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpWriteFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub mode: u32,
    pub only_if_missing: u8,
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
        encoder.write_byte(self.only_if_missing);
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 2, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let mode = decoder.read_u32_le()?;
        let only_if_missing = decoder.read_byte()?;
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
            only_if_missing,
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
            only_if_missing: o.only_if_missing,
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 3, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 4, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 6, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 5, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 7, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 8, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 10, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 9, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 11, got {}", kind)));
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
pub struct OpIptablesInput {
    pub table: std::string::String,
    pub chain: std::string::String,
    pub protocol: std::string::String,
    pub source: std::string::String,
    pub destination: std::string::String,
    pub source_port: std::string::String,
    pub destination_port: std::string::String,
    pub in_interface: std::string::String,
    pub out_interface: std::string::String,
    pub jump: std::string::String,
    pub ctstate: std::string::String,
    pub comment: std::string::String,
    pub ip_version: u8,
    pub action: u8,
    pub rule_state: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpIptablesOutput {
    pub kind: u8,
    pub table: std::string::String,
    pub chain: std::string::String,
    pub protocol: std::string::String,
    pub source: std::string::String,
    pub destination: std::string::String,
    pub source_port: std::string::String,
    pub destination_port: std::string::String,
    pub in_interface: std::string::String,
    pub out_interface: std::string::String,
    pub jump: std::string::String,
    pub ctstate: std::string::String,
    pub comment: std::string::String,
    pub ip_version: u8,
    pub action: u8,
    pub rule_state: u8,
}

pub type OpIptables = OpIptablesOutput;

impl OpIptablesInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(20);
        encoder.write_u16_le(self.table.len() as u16);
        let string_bytes: &[u8] = self.table.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.chain.len() as u16);
        let string_bytes: &[u8] = self.chain.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.protocol.len() as u16);
        let string_bytes: &[u8] = self.protocol.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.source.len() as u16);
        let string_bytes: &[u8] = self.source.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.destination.len() as u16);
        let string_bytes: &[u8] = self.destination.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.source_port.len() as u16);
        let string_bytes: &[u8] = self.source_port.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.destination_port.len() as u16);
        let string_bytes: &[u8] = self.destination_port.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.in_interface.len() as u16);
        let string_bytes: &[u8] = self.in_interface.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.out_interface.len() as u16);
        let string_bytes: &[u8] = self.out_interface.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.jump.len() as u16);
        let string_bytes: &[u8] = self.jump.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.ctstate.len() as u16);
        let string_bytes: &[u8] = self.ctstate.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.comment.len() as u16);
        let string_bytes: &[u8] = self.comment.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.ip_version);
        encoder.write_byte(self.action);
        encoder.write_byte(self.rule_state);
        Ok(())
    }

}

impl OpIptablesOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 20u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 20, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let table = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let chain = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let protocol = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let source = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let destination = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let source_port = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let destination_port = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let in_interface = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let out_interface = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let jump = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let ctstate = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let comment = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let ip_version = decoder.read_byte()?;
        let action = decoder.read_byte()?;
        let rule_state = decoder.read_byte()?;
        Ok(Self {
            kind,
            table,
            chain,
            protocol,
            source,
            destination,
            source_port,
            destination_port,
            in_interface,
            out_interface,
            jump,
            ctstate,
            comment,
            ip_version,
            action,
            rule_state,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpIptablesInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpIptablesInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpIptablesOutput> for OpIptablesInput {
    fn from(o: OpIptablesOutput) -> Self {
        Self {
            table: o.table,
            chain: o.chain,
            protocol: o.protocol,
            source: o.source,
            destination: o.destination,
            source_port: o.source_port,
            destination_port: o.destination_port,
            in_interface: o.in_interface,
            out_interface: o.out_interface,
            jump: o.jump,
            ctstate: o.ctstate,
            comment: o.comment,
            ip_version: o.ip_version,
            action: o.action,
            rule_state: o.rule_state,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpRepositoryInput {
    pub manager: u8,
    pub repo: std::string::String,
    pub state: u8,
    pub filename: std::string::String,
    pub mode: u32,
    pub update_cache: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpRepositoryOutput {
    pub kind: u8,
    pub manager: u8,
    pub repo: std::string::String,
    pub state: u8,
    pub filename: std::string::String,
    pub mode: u32,
    pub update_cache: u8,
}

pub type OpRepository = OpRepositoryOutput;

impl OpRepositoryInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(21);
        encoder.write_byte(self.manager);
        encoder.write_u16_le(self.repo.len() as u16);
        let string_bytes: &[u8] = self.repo.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_u16_le(self.filename.len() as u16);
        let string_bytes: &[u8] = self.filename.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.mode);
        encoder.write_byte(self.update_cache);
        Ok(())
    }

}

impl OpRepositoryOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 21u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 21, got {}", kind)));
        }
        let manager = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let repo = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let filename = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let mode = decoder.read_u32_le()?;
        let update_cache = decoder.read_byte()?;
        Ok(Self {
            kind,
            manager,
            repo,
            state,
            filename,
            mode,
            update_cache,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpRepositoryInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpRepositoryInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpRepositoryOutput> for OpRepositoryInput {
    fn from(o: OpRepositoryOutput) -> Self {
        Self {
            manager: o.manager,
            repo: o.repo,
            state: o.state,
            filename: o.filename,
            mode: o.mode,
            update_cache: o.update_cache,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGroupInput {
    pub name: std::string::String,
    pub state: u8,
    pub system: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGroupOutput {
    pub kind: u8,
    pub name: std::string::String,
    pub state: u8,
    pub system: u8,
}

pub type OpGroup = OpGroupOutput;

impl OpGroupInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(23);
        encoder.write_u16_le(self.name.len() as u16);
        let string_bytes: &[u8] = self.name.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.system);
        Ok(())
    }

}

impl OpGroupOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 23u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 23, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let name = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let system = decoder.read_byte()?;
        Ok(Self {
            kind,
            name,
            state,
            system,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpGroupInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpGroupInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpGroupOutput> for OpGroupInput {
    fn from(o: OpGroupOutput) -> Self {
        Self {
            name: o.name,
            state: o.state,
            system: o.system,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUserInput {
    pub name: std::string::String,
    pub state: u8,
    pub system: u8,
    pub has_shell: u8,
    pub shell: std::string::String,
    pub has_home: u8,
    pub home: std::string::String,
    pub create_home: u8,
    pub primary_group: std::string::String,
    pub groups: Vec<std::string::String>,
    pub append: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUserOutput {
    pub kind: u8,
    pub name: std::string::String,
    pub state: u8,
    pub system: u8,
    pub has_shell: u8,
    pub shell: std::string::String,
    pub has_home: u8,
    pub home: std::string::String,
    pub create_home: u8,
    pub primary_group: std::string::String,
    pub groups: Vec<std::string::String>,
    pub append: u8,
}

pub type OpUser = OpUserOutput;

impl OpUserInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(22);
        encoder.write_u16_le(self.name.len() as u16);
        let string_bytes: &[u8] = self.name.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.system);
        encoder.write_byte(self.has_shell);
        encoder.write_u16_le(self.shell.len() as u16);
        let string_bytes: &[u8] = self.shell.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.has_home);
        encoder.write_u16_le(self.home.len() as u16);
        let string_bytes: &[u8] = self.home.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.create_home);
        encoder.write_u16_le(self.primary_group.len() as u16);
        let string_bytes: &[u8] = self.primary_group.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.groups.len() as u16);
        for item in &self.groups {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_byte(self.append);
        Ok(())
    }

}

impl OpUserOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 22u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 22, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let name = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let system = decoder.read_byte()?;
        let has_shell = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let shell = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let has_home = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let home = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let create_home = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let primary_group = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let mut groups = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            groups.push(item);
        }
        let append = decoder.read_byte()?;
        Ok(Self {
            kind,
            name,
            state,
            system,
            has_shell,
            shell,
            has_home,
            home,
            create_home,
            primary_group,
            groups,
            append,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpUserInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpUserInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpUserOutput> for OpUserInput {
    fn from(o: OpUserOutput) -> Self {
        Self {
            name: o.name,
            state: o.state,
            system: o.system,
            has_shell: o.has_shell,
            shell: o.shell,
            has_home: o.has_home,
            home: o.home,
            create_home: o.create_home,
            primary_group: o.primary_group,
            groups: o.groups,
            append: o.append,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAuthorizedKeyInput {
    pub user: std::string::String,
    pub key: std::string::String,
    pub state: u8,
    pub exclusive: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAuthorizedKeyOutput {
    pub kind: u8,
    pub user: std::string::String,
    pub key: std::string::String,
    pub state: u8,
    pub exclusive: u8,
}

pub type OpAuthorizedKey = OpAuthorizedKeyOutput;

impl OpAuthorizedKeyInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(24);
        encoder.write_u16_le(self.user.len() as u16);
        let string_bytes: &[u8] = self.user.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.key.len() as u16);
        let string_bytes: &[u8] = self.key.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_byte(self.exclusive);
        Ok(())
    }

}

impl OpAuthorizedKeyOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 24u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 24, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let user = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let key = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let exclusive = decoder.read_byte()?;
        Ok(Self {
            kind,
            user,
            key,
            state,
            exclusive,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpAuthorizedKeyInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpAuthorizedKeyInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpAuthorizedKeyOutput> for OpAuthorizedKeyInput {
    fn from(o: OpAuthorizedKeyOutput) -> Self {
        Self {
            user: o.user,
            key: o.key,
            state: o.state,
            exclusive: o.exclusive,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGetentInput {
    pub database: std::string::String,
    pub key: std::string::String,
    pub fail_key: u8,
    pub split: std::string::String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGetentOutput {
    pub kind: u8,
    pub database: std::string::String,
    pub key: std::string::String,
    pub fail_key: u8,
    pub split: std::string::String,
}

pub type OpGetent = OpGetentOutput;

impl OpGetentInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(25);
        encoder.write_u16_le(self.database.len() as u16);
        let string_bytes: &[u8] = self.database.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.key.len() as u16);
        let string_bytes: &[u8] = self.key.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.fail_key);
        encoder.write_u16_le(self.split.len() as u16);
        let string_bytes: &[u8] = self.split.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        Ok(())
    }

}

impl OpGetentOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 25u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 25, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let database = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let key = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let fail_key = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let split = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        Ok(Self {
            kind,
            database,
            key,
            fail_key,
            split,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpGetentInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpGetentInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpGetentOutput> for OpGetentInput {
    fn from(o: OpGetentOutput) -> Self {
        Self {
            database: o.database,
            key: o.key,
            fail_key: o.fail_key,
            split: o.split,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpHostnameInput {
    pub name: std::string::String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpHostnameOutput {
    pub kind: u8,
    pub name: std::string::String,
}

pub type OpHostname = OpHostnameOutput;

impl OpHostnameInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(26);
        encoder.write_u16_le(self.name.len() as u16);
        let string_bytes: &[u8] = self.name.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        Ok(())
    }

}

impl OpHostnameOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 26u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 26, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let name = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        Ok(Self {
            kind,
            name,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpHostnameInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpHostnameInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpHostnameOutput> for OpHostnameInput {
    fn from(o: OpHostnameOutput) -> Self {
        Self {
            name: o.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUriInput {
    pub method: u8,
    pub url: std::string::String,
    pub header_keys: Vec<std::string::String>,
    pub header_values: Vec<std::string::String>,
    pub body: Vec<u8>,
    pub body_format: u8,
    pub status_codes: Vec<u16>,
    pub timeout_ms: u32,
    pub return_content: u8,
    pub validate_certs: u8,
    pub follow_redirects: u8,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_bundle_pem: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUriOutput {
    pub kind: u8,
    pub method: u8,
    pub url: std::string::String,
    pub header_keys: Vec<std::string::String>,
    pub header_values: Vec<std::string::String>,
    pub body: Vec<u8>,
    pub body_format: u8,
    pub status_codes: Vec<u16>,
    pub timeout_ms: u32,
    pub return_content: u8,
    pub validate_certs: u8,
    pub follow_redirects: u8,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_bundle_pem: Vec<u8>,
}

pub type OpUri = OpUriOutput;

impl OpUriInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(12);
        encoder.write_byte(self.method);
        encoder.write_u16_le(self.url.len() as u16);
        let string_bytes: &[u8] = self.url.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.header_keys.len() as u16);
        for item in &self.header_keys {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.header_values.len() as u16);
        for item in &self.header_values {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u32_le(self.body.len() as u32);
        for item in &self.body {
            encoder.write_byte(*item);
        }
        encoder.write_byte(self.body_format);
        encoder.write_u16_le(self.status_codes.len() as u16);
        for item in &self.status_codes {
            encoder.write_u16_le(*item);
        }
        encoder.write_u32_le(self.timeout_ms);
        encoder.write_byte(self.return_content);
        encoder.write_byte(self.validate_certs);
        encoder.write_byte(self.follow_redirects);
        encoder.write_u32_le(self.client_cert_pem.len() as u32);
        for item in &self.client_cert_pem {
            encoder.write_byte(*item);
        }
        encoder.write_u32_le(self.client_key_pem.len() as u32);
        for item in &self.client_key_pem {
            encoder.write_byte(*item);
        }
        encoder.write_u32_le(self.ca_bundle_pem.len() as u32);
        for item in &self.ca_bundle_pem {
            encoder.write_byte(*item);
        }
        Ok(())
    }

}

impl OpUriOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 12u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 12, got {}", kind)));
        }
        let method = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let url = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let mut header_keys = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            header_keys.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let mut header_values = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            header_values.push(item);
        }
        let length = decoder.read_u32_le()? as usize;
        let mut body = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            body.push(item);
        }
        let body_format = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let mut status_codes = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_u16_le()?;
            status_codes.push(item);
        }
        let timeout_ms = decoder.read_u32_le()?;
        let return_content = decoder.read_byte()?;
        let validate_certs = decoder.read_byte()?;
        let follow_redirects = decoder.read_byte()?;
        let length = decoder.read_u32_le()? as usize;
        let mut client_cert_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            client_cert_pem.push(item);
        }
        let length = decoder.read_u32_le()? as usize;
        let mut client_key_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            client_key_pem.push(item);
        }
        let length = decoder.read_u32_le()? as usize;
        let mut ca_bundle_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            ca_bundle_pem.push(item);
        }
        Ok(Self {
            kind,
            method,
            url,
            header_keys,
            header_values,
            body,
            body_format,
            status_codes,
            timeout_ms,
            return_content,
            validate_certs,
            follow_redirects,
            client_cert_pem,
            client_key_pem,
            ca_bundle_pem,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpUriInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpUriInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpUriOutput> for OpUriInput {
    fn from(o: OpUriOutput) -> Self {
        Self {
            method: o.method,
            url: o.url,
            header_keys: o.header_keys,
            header_values: o.header_values,
            body: o.body,
            body_format: o.body_format,
            status_codes: o.status_codes,
            timeout_ms: o.timeout_ms,
            return_content: o.return_content,
            validate_certs: o.validate_certs,
            follow_redirects: o.follow_redirects,
            client_cert_pem: o.client_cert_pem,
            client_key_pem: o.client_key_pem,
            ca_bundle_pem: o.ca_bundle_pem,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPostgresqlQueryInput {
    pub query: std::string::String,
    pub db: std::string::String,
    pub login_user: std::string::String,
    pub login_password: std::string::String,
    pub login_unix_socket: std::string::String,
    pub login_host: std::string::String,
    pub login_port: u16,
    pub autocommit: u8,
    pub positional_args: Vec<std::string::String>,
    pub read_only: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPostgresqlQueryOutput {
    pub kind: u8,
    pub query: std::string::String,
    pub db: std::string::String,
    pub login_user: std::string::String,
    pub login_password: std::string::String,
    pub login_unix_socket: std::string::String,
    pub login_host: std::string::String,
    pub login_port: u16,
    pub autocommit: u8,
    pub positional_args: Vec<std::string::String>,
    pub read_only: u8,
}

pub type OpPostgresqlQuery = OpPostgresqlQueryOutput;

impl OpPostgresqlQueryInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(13);
        encoder.write_u32_le(self.query.len() as u32);
        let string_bytes: &[u8] = self.query.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.db.len() as u16);
        let string_bytes: &[u8] = self.db.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_user.len() as u16);
        let string_bytes: &[u8] = self.login_user.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_password.len() as u16);
        let string_bytes: &[u8] = self.login_password.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_unix_socket.len() as u16);
        let string_bytes: &[u8] = self.login_unix_socket.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_host.len() as u16);
        let string_bytes: &[u8] = self.login_host.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_port);
        encoder.write_byte(self.autocommit);
        encoder.write_u16_le(self.positional_args.len() as u16);
        for item in &self.positional_args {
            encoder.write_u32_le(item.len() as u32);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_byte(self.read_only);
        Ok(())
    }

}

impl OpPostgresqlQueryOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 13u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 13, got {}", kind)));
        }
        let length = decoder.read_u32_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let query = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let db = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_user = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_password = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_unix_socket = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_host = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let login_port = decoder.read_u16_le()?;
        let autocommit = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let mut positional_args = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u32_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            positional_args.push(item);
        }
        let read_only = decoder.read_byte()?;
        Ok(Self {
            kind,
            query,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
            autocommit,
            positional_args,
            read_only,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpPostgresqlQueryInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpPostgresqlQueryInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpPostgresqlQueryOutput> for OpPostgresqlQueryInput {
    fn from(o: OpPostgresqlQueryOutput) -> Self {
        Self {
            query: o.query,
            db: o.db,
            login_user: o.login_user,
            login_password: o.login_password,
            login_unix_socket: o.login_unix_socket,
            login_host: o.login_host,
            login_port: o.login_port,
            autocommit: o.autocommit,
            positional_args: o.positional_args,
            read_only: o.read_only,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPostgresqlExtInput {
    pub name: std::string::String,
    pub state: u8,
    pub version: std::string::String,
    pub ext_schema: std::string::String,
    pub cascade: u8,
    pub db: std::string::String,
    pub login_user: std::string::String,
    pub login_password: std::string::String,
    pub login_unix_socket: std::string::String,
    pub login_host: std::string::String,
    pub login_port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpPostgresqlExtOutput {
    pub kind: u8,
    pub name: std::string::String,
    pub state: u8,
    pub version: std::string::String,
    pub ext_schema: std::string::String,
    pub cascade: u8,
    pub db: std::string::String,
    pub login_user: std::string::String,
    pub login_password: std::string::String,
    pub login_unix_socket: std::string::String,
    pub login_host: std::string::String,
    pub login_port: u16,
}

pub type OpPostgresqlExt = OpPostgresqlExtOutput;

impl OpPostgresqlExtInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(14);
        encoder.write_u16_le(self.name.len() as u16);
        let string_bytes: &[u8] = self.name.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.state);
        encoder.write_u16_le(self.version.len() as u16);
        let string_bytes: &[u8] = self.version.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.ext_schema.len() as u16);
        let string_bytes: &[u8] = self.ext_schema.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.cascade);
        encoder.write_u16_le(self.db.len() as u16);
        let string_bytes: &[u8] = self.db.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_user.len() as u16);
        let string_bytes: &[u8] = self.login_user.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_password.len() as u16);
        let string_bytes: &[u8] = self.login_password.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_unix_socket.len() as u16);
        let string_bytes: &[u8] = self.login_unix_socket.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_host.len() as u16);
        let string_bytes: &[u8] = self.login_host.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.login_port);
        Ok(())
    }

}

impl OpPostgresqlExtOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 14u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 14, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let name = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let state = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let version = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let ext_schema = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let cascade = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let db = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_user = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_password = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_unix_socket = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let login_host = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let login_port = decoder.read_u16_le()?;
        Ok(Self {
            kind,
            name,
            state,
            version,
            ext_schema,
            cascade,
            db,
            login_user,
            login_password,
            login_unix_socket,
            login_host,
            login_port,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpPostgresqlExtInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpPostgresqlExtInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpPostgresqlExtOutput> for OpPostgresqlExtInput {
    fn from(o: OpPostgresqlExtOutput) -> Self {
        Self {
            name: o.name,
            state: o.state,
            version: o.version,
            ext_schema: o.ext_schema,
            cascade: o.cascade,
            db: o.db,
            login_user: o.login_user,
            login_password: o.login_password,
            login_unix_socket: o.login_unix_socket,
            login_host: o.login_host,
            login_port: o.login_port,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGetUrlInput {
    pub url: std::string::String,
    pub dest: std::string::String,
    pub checksum: std::string::String,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub header_keys: Vec<std::string::String>,
    pub header_values: Vec<std::string::String>,
    pub timeout_ms: u32,
    pub force: u8,
    pub validate_certs: u8,
    pub follow_redirects: u8,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_bundle_pem: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpGetUrlOutput {
    pub kind: u8,
    pub url: std::string::String,
    pub dest: std::string::String,
    pub checksum: std::string::String,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub header_keys: Vec<std::string::String>,
    pub header_values: Vec<std::string::String>,
    pub timeout_ms: u32,
    pub force: u8,
    pub validate_certs: u8,
    pub follow_redirects: u8,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_bundle_pem: Vec<u8>,
}

pub type OpGetUrl = OpGetUrlOutput;

impl OpGetUrlInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(15);
        encoder.write_u16_le(self.url.len() as u16);
        let string_bytes: &[u8] = self.url.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.dest.len() as u16);
        let string_bytes: &[u8] = self.dest.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.checksum.len() as u16);
        let string_bytes: &[u8] = self.checksum.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
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
        encoder.write_u16_le(self.header_keys.len() as u16);
        for item in &self.header_keys {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.header_values.len() as u16);
        for item in &self.header_values {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u32_le(self.timeout_ms);
        encoder.write_byte(self.force);
        encoder.write_byte(self.validate_certs);
        encoder.write_byte(self.follow_redirects);
        encoder.write_u32_le(self.client_cert_pem.len() as u32);
        for item in &self.client_cert_pem {
            encoder.write_byte(*item);
        }
        encoder.write_u32_le(self.client_key_pem.len() as u32);
        for item in &self.client_key_pem {
            encoder.write_byte(*item);
        }
        encoder.write_u32_le(self.ca_bundle_pem.len() as u32);
        for item in &self.ca_bundle_pem {
            encoder.write_byte(*item);
        }
        Ok(())
    }

}

impl OpGetUrlOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 15u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 15, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let url = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let dest = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let checksum = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let mode = decoder.read_u32_le()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let owner = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let group = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let mut header_keys = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            header_keys.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let mut header_values = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            header_values.push(item);
        }
        let timeout_ms = decoder.read_u32_le()?;
        let force = decoder.read_byte()?;
        let validate_certs = decoder.read_byte()?;
        let follow_redirects = decoder.read_byte()?;
        let length = decoder.read_u32_le()? as usize;
        let mut client_cert_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            client_cert_pem.push(item);
        }
        let length = decoder.read_u32_le()? as usize;
        let mut client_key_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            client_key_pem.push(item);
        }
        let length = decoder.read_u32_le()? as usize;
        let mut ca_bundle_pem = Vec::with_capacity(length);
        for _ in 0..length {
            let item = decoder.read_byte()?;
            ca_bundle_pem.push(item);
        }
        Ok(Self {
            kind,
            url,
            dest,
            checksum,
            mode,
            owner,
            group,
            header_keys,
            header_values,
            timeout_ms,
            force,
            validate_certs,
            follow_redirects,
            client_cert_pem,
            client_key_pem,
            ca_bundle_pem,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpGetUrlInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpGetUrlInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpGetUrlOutput> for OpGetUrlInput {
    fn from(o: OpGetUrlOutput) -> Self {
        Self {
            url: o.url,
            dest: o.dest,
            checksum: o.checksum,
            mode: o.mode,
            owner: o.owner,
            group: o.group,
            header_keys: o.header_keys,
            header_values: o.header_values,
            timeout_ms: o.timeout_ms,
            force: o.force,
            validate_certs: o.validate_certs,
            follow_redirects: o.follow_redirects,
            client_cert_pem: o.client_cert_pem,
            client_key_pem: o.client_key_pem,
            ca_bundle_pem: o.ca_bundle_pem,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAsyncStartInput {
    pub timeout_ms: u32,
    pub inner: Box<Op>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAsyncStartOutput {
    pub kind: u8,
    pub timeout_ms: u32,
    pub inner: Box<Op>,
}

pub type OpAsyncStart = OpAsyncStartOutput;

impl OpAsyncStartInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(16);
        encoder.write_u32_le(self.timeout_ms);
        self.inner.encode_into(encoder)?;
        Ok(())
    }

}

impl OpAsyncStartOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 16u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 16, got {}", kind)));
        }
        let timeout_ms = decoder.read_u32_le()?;
        let inner = Op::decode_with_decoder(decoder)?;
        Ok(Self {
            kind,
            timeout_ms,
            inner: Box::new(inner),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpAsyncStartInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpAsyncStartInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpAsyncStartOutput> for OpAsyncStartInput {
    fn from(o: OpAsyncStartOutput) -> Self {
        Self {
            timeout_ms: o.timeout_ms,
            inner: o.inner,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAsyncStatusInput {
    pub job_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpAsyncStatusOutput {
    pub kind: u8,
    pub job_id: u32,
}

pub type OpAsyncStatus = OpAsyncStatusOutput;

impl OpAsyncStatusInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(17);
        encoder.write_u32_le(self.job_id);
        Ok(())
    }

}

impl OpAsyncStatusOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 17u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 17, got {}", kind)));
        }
        let job_id = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            job_id,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpAsyncStatusInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpAsyncStatusInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpAsyncStatusOutput> for OpAsyncStatusInput {
    fn from(o: OpAsyncStatusOutput) -> Self {
        Self {
            job_id: o.job_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpReadFileInput {
    pub path: std::string::String,
    pub max_bytes: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpReadFileOutput {
    pub kind: u8,
    pub path: std::string::String,
    pub max_bytes: u32,
}

pub type OpReadFile = OpReadFileOutput;

impl OpReadFileInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(18);
        encoder.write_u16_le(self.path.len() as u16);
        let string_bytes: &[u8] = self.path.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u32_le(self.max_bytes);
        Ok(())
    }

}

impl OpReadFileOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 18u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 18, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let path = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let max_bytes = decoder.read_u32_le()?;
        Ok(Self {
            kind,
            path,
            max_bytes,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpReadFileInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpReadFileInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpReadFileOutput> for OpReadFileInput {
    fn from(o: OpReadFileOutput) -> Self {
        Self {
            path: o.path,
            max_bytes: o.max_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUnarchiveInput {
    pub src: std::string::String,
    pub dest: std::string::String,
    pub format: u8,
    pub creates: std::string::String,
    pub has_mode: u8,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub keep_newer: u8,
    pub list_files: u8,
    pub include: Vec<std::string::String>,
    pub exclude: Vec<std::string::String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpUnarchiveOutput {
    pub kind: u8,
    pub src: std::string::String,
    pub dest: std::string::String,
    pub format: u8,
    pub creates: std::string::String,
    pub has_mode: u8,
    pub mode: u32,
    pub owner: std::string::String,
    pub group: std::string::String,
    pub keep_newer: u8,
    pub list_files: u8,
    pub include: Vec<std::string::String>,
    pub exclude: Vec<std::string::String>,
}

pub type OpUnarchive = OpUnarchiveOutput;

impl OpUnarchiveInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut encoder = BitStreamEncoder::new(BitOrder::MsbFirst);
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }

    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        encoder.write_byte(19);
        encoder.write_u16_le(self.src.len() as u16);
        let string_bytes: &[u8] = self.src.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_u16_le(self.dest.len() as u16);
        let string_bytes: &[u8] = self.dest.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
        encoder.write_byte(self.format);
        encoder.write_u16_le(self.creates.len() as u16);
        let string_bytes: &[u8] = self.creates.as_bytes();
        for &b in string_bytes.iter() {
            encoder.write_byte(b);
        }
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
        encoder.write_byte(self.keep_newer);
        encoder.write_byte(self.list_files);
        encoder.write_u16_le(self.include.len() as u16);
        for item in &self.include {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        encoder.write_u16_le(self.exclude.len() as u16);
        for item in &self.exclude {
            encoder.write_u16_le(item.len() as u16);
            for b in item.as_bytes() {
                encoder.write_byte(*b);
            }
        }
        Ok(())
    }

}

impl OpUnarchiveOutput {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = BitStreamDecoder::new(bytes, BitOrder::MsbFirst);
        Self::decode_with_decoder(&mut decoder)
    }

    pub fn decode_with_decoder(decoder: &mut BitStreamDecoder) -> Result<Self> {
        let kind = decoder.read_byte()?;
        if kind != 19u8 {
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 19, got {}", kind)));
        }
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let src = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let dest = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let format = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let creates = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let has_mode = decoder.read_byte()?;
        let mode = decoder.read_u32_le()?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let owner = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let length = decoder.read_u16_le()? as usize;
        let bytes = decoder.read_bytes_vec(length)?;
        let group = std::string::String::from_utf8(bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
        let keep_newer = decoder.read_byte()?;
        let list_files = decoder.read_byte()?;
        let length = decoder.read_u16_le()? as usize;
        let mut include = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            include.push(item);
        }
        let length = decoder.read_u16_le()? as usize;
        let mut exclude = Vec::with_capacity(length);
        for _ in 0..length {
            let str_len = decoder.read_u16_le()? as usize;
            let str_bytes = decoder.read_bytes_vec(str_len)?;
            let item = std::string::String::from_utf8(str_bytes).map_err(|_| binschema_runtime::BinSchemaError::InvalidUtf8)?;
            exclude.push(item);
        }
        Ok(Self {
            kind,
            src,
            dest,
            format,
            creates,
            has_mode,
            mode,
            owner,
            group,
            keep_newer,
            list_files,
            include,
            exclude,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        OpUnarchiveInput::from(self.clone()).encode()
    }
    pub fn encode_into(&self, encoder: &mut BitStreamEncoder) -> Result<()> {
        OpUnarchiveInput::from(self.clone()).encode_into(encoder)
    }
}

impl From<OpUnarchiveOutput> for OpUnarchiveInput {
    fn from(o: OpUnarchiveOutput) -> Self {
        Self {
            src: o.src,
            dest: o.dest,
            format: o.format,
            creates: o.creates,
            has_mode: o.has_mode,
            mode: o.mode,
            owner: o.owner,
            group: o.group,
            keep_newer: o.keep_newer,
            list_files: o.list_files,
            include: o.include,
            exclude: o.exclude,
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
    OpUri(OpUriOutput),
    OpPostgresqlQuery(OpPostgresqlQueryOutput),
    OpPostgresqlExt(OpPostgresqlExtOutput),
    OpGetUrl(OpGetUrlOutput),
    OpAsyncStart(OpAsyncStartOutput),
    OpAsyncStatus(OpAsyncStatusOutput),
    OpReadFile(OpReadFileOutput),
    OpUnarchive(OpUnarchiveOutput),
    OpIptables(OpIptablesOutput),
    OpRepository(OpRepositoryOutput),
    OpUser(OpUserOutput),
    OpGroup(OpGroupOutput),
    OpAuthorizedKey(OpAuthorizedKeyOutput),
    OpGetent(OpGetentOutput),
    OpHostname(OpHostnameOutput),
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
                encoder.write_uint8(v.only_if_missing);
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
            Op::OpUri(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint8(v.method);
                encoder.write_uint16(v.url.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.url.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.header_keys.len() as u16, Endianness::LittleEndian);
                for item in &v.header_keys {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.header_values.len() as u16, Endianness::LittleEndian);
                for item in &v.header_values {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint32(v.body.len() as u32, Endianness::LittleEndian);
                for item in &v.body {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint8(v.body_format);
                encoder.write_uint16(v.status_codes.len() as u16, Endianness::LittleEndian);
                for item in &v.status_codes {
                    encoder.write_uint16(*item, Endianness::LittleEndian);
                }
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
                encoder.write_uint8(v.return_content);
                encoder.write_uint8(v.validate_certs);
                encoder.write_uint8(v.follow_redirects);
                encoder.write_uint32(v.client_cert_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.client_cert_pem {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint32(v.client_key_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.client_key_pem {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint32(v.ca_bundle_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.ca_bundle_pem {
                    encoder.write_uint8(*item);
                }
            }
            Op::OpPostgresqlQuery(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.query.len() as u32, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.query.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.db.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.db.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_user.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_user.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_password.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_password.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_unix_socket.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_unix_socket.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_host.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_host.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_port, Endianness::LittleEndian);
                encoder.write_uint8(v.autocommit);
                encoder.write_uint16(v.positional_args.len() as u16, Endianness::LittleEndian);
                for item in &v.positional_args {
                    encoder.write_uint32(item.len() as u32, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint8(v.read_only);
            }
            Op::OpPostgresqlExt(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.name.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.name.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint16(v.version.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.version.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.ext_schema.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.ext_schema.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.cascade);
                encoder.write_uint16(v.db.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.db.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_user.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_user.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_password.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_password.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_unix_socket.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_unix_socket.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_host.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.login_host.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.login_port, Endianness::LittleEndian);
            }
            Op::OpGetUrl(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.url.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.url.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.dest.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.dest.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.checksum.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.checksum.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
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
                encoder.write_uint16(v.header_keys.len() as u16, Endianness::LittleEndian);
                for item in &v.header_keys {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.header_values.len() as u16, Endianness::LittleEndian);
                for item in &v.header_values {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
                encoder.write_uint8(v.force);
                encoder.write_uint8(v.validate_certs);
                encoder.write_uint8(v.follow_redirects);
                encoder.write_uint32(v.client_cert_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.client_cert_pem {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint32(v.client_key_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.client_key_pem {
                    encoder.write_uint8(*item);
                }
                encoder.write_uint32(v.ca_bundle_pem.len() as u32, Endianness::LittleEndian);
                for item in &v.ca_bundle_pem {
                    encoder.write_uint8(*item);
                }
            }
            Op::OpAsyncStart(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.timeout_ms, Endianness::LittleEndian);
                v.inner.encode_into(encoder)?;
            }
            Op::OpAsyncStatus(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint32(v.job_id, Endianness::LittleEndian);
            }
            Op::OpReadFile(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.path.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.path.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.max_bytes, Endianness::LittleEndian);
            }
            Op::OpUnarchive(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.src.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.src.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.dest.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.dest.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.format);
                encoder.write_uint16(v.creates.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.creates.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
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
                encoder.write_uint8(v.keep_newer);
                encoder.write_uint8(v.list_files);
                encoder.write_uint16(v.include.len() as u16, Endianness::LittleEndian);
                for item in &v.include {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint16(v.exclude.len() as u16, Endianness::LittleEndian);
                for item in &v.exclude {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
            }
            Op::OpIptables(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.table.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.table.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.chain.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.chain.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.protocol.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.protocol.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.source.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.source.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.destination.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.destination.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.source_port.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.source_port.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.destination_port.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.destination_port.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.in_interface.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.in_interface.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.out_interface.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.out_interface.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.jump.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.jump.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.ctstate.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.ctstate.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.comment.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.comment.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.ip_version);
                encoder.write_uint8(v.action);
                encoder.write_uint8(v.rule_state);
            }
            Op::OpRepository(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint8(v.manager);
                encoder.write_uint16(v.repo.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.repo.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint16(v.filename.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.filename.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint32(v.mode, Endianness::LittleEndian);
                encoder.write_uint8(v.update_cache);
            }
            Op::OpUser(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.name.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.name.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.system);
                encoder.write_uint8(v.has_shell);
                encoder.write_uint16(v.shell.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.shell.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.has_home);
                encoder.write_uint16(v.home.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.home.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.create_home);
                encoder.write_uint16(v.primary_group.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.primary_group.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.groups.len() as u16, Endianness::LittleEndian);
                for item in &v.groups {
                    encoder.write_uint16(item.len() as u16, Endianness::LittleEndian);
                    for b in item.as_bytes() {
                        encoder.write_uint8(*b);
                    }
                }
                encoder.write_uint8(v.append);
            }
            Op::OpGroup(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.name.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.name.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.system);
            }
            Op::OpAuthorizedKey(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.user.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.user.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.key.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.key.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.state);
                encoder.write_uint8(v.exclusive);
            }
            Op::OpGetent(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.database.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.database.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint16(v.key.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.key.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
                encoder.write_uint8(v.fail_key);
                encoder.write_uint16(v.split.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.split.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
            }
            Op::OpHostname(v) => {
                encoder.write_uint8(v.kind);
                encoder.write_uint16(v.name.len() as u16, Endianness::LittleEndian);
                let string_bytes: &[u8] = v.name.as_bytes();
                for &b in string_bytes.iter() {
                    encoder.write_uint8(b);
                }
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
        } else if value == 12 {
            Ok(Op::OpUri(OpUriOutput::decode_with_decoder(decoder)?))
        } else if value == 13 {
            Ok(Op::OpPostgresqlQuery(OpPostgresqlQueryOutput::decode_with_decoder(decoder)?))
        } else if value == 14 {
            Ok(Op::OpPostgresqlExt(OpPostgresqlExtOutput::decode_with_decoder(decoder)?))
        } else if value == 15 {
            Ok(Op::OpGetUrl(OpGetUrlOutput::decode_with_decoder(decoder)?))
        } else if value == 16 {
            Ok(Op::OpAsyncStart(OpAsyncStartOutput::decode_with_decoder(decoder)?))
        } else if value == 17 {
            Ok(Op::OpAsyncStatus(OpAsyncStatusOutput::decode_with_decoder(decoder)?))
        } else if value == 18 {
            Ok(Op::OpReadFile(OpReadFileOutput::decode_with_decoder(decoder)?))
        } else if value == 19 {
            Ok(Op::OpUnarchive(OpUnarchiveOutput::decode_with_decoder(decoder)?))
        } else if value == 20 {
            Ok(Op::OpIptables(OpIptablesOutput::decode_with_decoder(decoder)?))
        } else if value == 21 {
            Ok(Op::OpRepository(OpRepositoryOutput::decode_with_decoder(decoder)?))
        } else if value == 22 {
            Ok(Op::OpUser(OpUserOutput::decode_with_decoder(decoder)?))
        } else if value == 23 {
            Ok(Op::OpGroup(OpGroupOutput::decode_with_decoder(decoder)?))
        } else if value == 24 {
            Ok(Op::OpAuthorizedKey(OpAuthorizedKeyOutput::decode_with_decoder(decoder)?))
        } else if value == 25 {
            Ok(Op::OpGetent(OpGetentOutput::decode_with_decoder(decoder)?))
        } else if value == 26 {
            Ok(Op::OpHostname(OpHostnameOutput::decode_with_decoder(decoder)?))
        } else {
            Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("unknown discriminator value: {}", value)))
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 0, got {}", kind)));
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
    pub check_mode: u8,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDispatchOutput {
    pub kind: u8,
    pub seq: u32,
    pub check_mode: u8,
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
        encoder.write_byte(self.check_mode);
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 1, got {}", kind)));
        }
        let seq = decoder.read_u32_le()?;
        let check_mode = decoder.read_byte()?;
        let op = Op::decode_with_decoder(decoder)?;
        Ok(Self {
            kind,
            seq,
            check_mode,
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
            check_mode: o.check_mode,
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 2, got {}", kind)));
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
    pub skipped: u8,
    pub started_unix_ns: u64,
    pub finished_unix_ns: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDoneOutput {
    pub kind: u8,
    pub seq: u32,
    pub exit_code: i32,
    pub changed: u8,
    pub skipped: u8,
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
        encoder.write_byte(self.skipped);
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 3, got {}", kind)));
        }
        let seq = decoder.read_u32_le()?;
        let exit_code = decoder.read_u32_le()? as i32;
        let changed = decoder.read_byte()?;
        let skipped = decoder.read_byte()?;
        let started_unix_ns = decoder.read_u64_le()?;
        let finished_unix_ns = decoder.read_u64_le()?;
        Ok(Self {
            kind,
            seq,
            exit_code,
            changed,
            skipped,
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
            skipped: o.skipped,
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 4, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 5, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 6, got {}", kind)));
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
            return Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("expected 7, got {}", kind)));
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
                encoder.write_uint8(v.check_mode);
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
                encoder.write_uint8(v.skipped);
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
            Err(binschema_runtime::BinSchemaError::InvalidVariant(format!("unknown discriminator value: {}", value)))
        }
    }
}
