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
pub enum Op {
    OpExec(OpExecOutput),
    OpShell(OpShellOutput),
    OpWriteFile(OpWriteFileOutput),
    OpGatherFacts(OpGatherFactsOutput),
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
