// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! efivarfs — EFI Variables Filesystem.
//!
//! Exposes UEFI runtime variables as files under a virtual filesystem.
//! Each file corresponds to a single EFI variable, named using the format:
//!
//! ```text
//! <VariableName>-<VendorGUID>
//! ```
//!
//! For example:
//! ```text
//! Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c
//! ```
//!
//! # Variable attributes
//!
//! Each variable has UEFI attribute flags that control persistence,
//! boot-time access, and runtime access.  The attributes are stored
//! as a 4-byte little-endian prefix in the file content.
//!
//! # Immutable variables
//!
//! Certain variables (e.g., `SecureBoot`, `PK`) are marked immutable
//! and cannot be deleted or overwritten through the filesystem.
//!
//! # Reference
//!
//! UEFI Specification 2.10, Section 8 (Runtime Services — Variable Services).
//! Linux `fs/efivarfs/`.

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// efivarfs magic number (same as Linux: `0xde5e81e4`).
pub const EFIVARFS_MAGIC: u32 = 0xde5e81e4;

/// Maximum variable name length in bytes (UTF-8).
const MAX_VAR_NAME_LEN: usize = 255;

/// Maximum variable data size (64 KiB, typical UEFI firmware limit).
const MAX_VAR_DATA_SIZE: usize = 65536;

/// Maximum number of variables.
const MAX_VARIABLES: usize = 512;

/// Maximum inodes (1 root + MAX_VARIABLES).
const MAX_INODES: usize = MAX_VARIABLES + 1;

/// Attribute prefix size in file content (4 bytes LE).
const ATTR_PREFIX_SIZE: usize = 4;

/// GUID string length (e.g., "8be4df61-93ca-11d2-aa0d-00e098032b8c").
const GUID_STRING_LEN: usize = 36;

// ── GUID handling ────────────────────────────────────────────────────────────

/// EFI GUID (128-bit Globally Unique Identifier).
///
/// Stored in mixed-endian format as per the UEFI specification:
/// - `data1`: LE 32-bit
/// - `data2`: LE 16-bit
/// - `data3`: LE 16-bit
/// - `data4`: big-endian 8 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiGuid {
    /// First 32-bit field (little-endian on disk).
    pub data1: u32,
    /// Second 16-bit field.
    pub data2: u16,
    /// Third 16-bit field.
    pub data3: u16,
    /// Last 8 bytes (big-endian).
    pub data4: [u8; 8],
}

impl EfiGuid {
    /// Well-known EFI Global Variable vendor GUID.
    pub const EFI_GLOBAL_VARIABLE: Self = Self {
        data1: 0x8be4df61,
        data2: 0x93ca,
        data3: 0x11d2,
        data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    };

    /// Linux EFI variable vendor GUID.
    pub const LINUX_EFI_GUID: Self = Self {
        data1: 0xadf956ad,
        data2: 0xe98c,
        data3: 0x11d3,
        data4: [0xbb, 0xbf, 0x00, 0x80, 0xc7, 0xd0, 0x42, 0x98],
    };

    /// Null GUID.
    pub const NULL: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    /// Format as a string: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
    pub fn to_string(&self) -> String {
        let mut s = String::with_capacity(GUID_STRING_LEN);
        write_hex_u32(&mut s, self.data1);
        s.push('-');
        write_hex_u16(&mut s, self.data2);
        s.push('-');
        write_hex_u16(&mut s, self.data3);
        s.push('-');
        write_hex_u8(&mut s, self.data4[0]);
        write_hex_u8(&mut s, self.data4[1]);
        s.push('-');
        for &b in &self.data4[2..] {
            write_hex_u8(&mut s, b);
        }
        s
    }

    /// Parse a GUID from a string.
    pub fn from_string(s: &str) -> Result<Self> {
        if s.len() != GUID_STRING_LEN {
            return Err(Error::InvalidArgument);
        }
        let bytes = s.as_bytes();
        // Expected format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        // Positions:       0       8 9   13 14  18 19  23 24          35
        if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
            return Err(Error::InvalidArgument);
        }
        let data1 = parse_hex_u32(&bytes[0..8])?;
        let data2 = parse_hex_u16(&bytes[9..13])?;
        let data3 = parse_hex_u16(&bytes[14..18])?;
        let d4a = parse_hex_u8(&bytes[19..21])?;
        let d4b = parse_hex_u8(&bytes[21..23])?;
        let mut data4 = [0u8; 8];
        data4[0] = d4a;
        data4[1] = d4b;
        let mut idx = 24;
        for slot in &mut data4[2..] {
            *slot = parse_hex_u8(&bytes[idx..idx + 2])?;
            idx += 2;
        }
        Ok(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }
}

// ── Hex formatting helpers ───────────────────────────────────────────────────

fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + n - 10,
        _ => b'0',
    }
}

fn write_hex_u8(s: &mut String, v: u8) {
    s.push(hex_nibble(v >> 4) as char);
    s.push(hex_nibble(v & 0xF) as char);
}

fn write_hex_u16(s: &mut String, v: u16) {
    write_hex_u8(s, (v >> 8) as u8);
    write_hex_u8(s, v as u8);
}

fn write_hex_u32(s: &mut String, v: u32) {
    write_hex_u16(s, (v >> 16) as u16);
    write_hex_u16(s, v as u16);
}

fn parse_hex_nibble(ch: u8) -> Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(Error::InvalidArgument),
    }
}

fn parse_hex_u8(bytes: &[u8]) -> Result<u8> {
    if bytes.len() < 2 {
        return Err(Error::InvalidArgument);
    }
    let hi = parse_hex_nibble(bytes[0])?;
    let lo = parse_hex_nibble(bytes[1])?;
    Ok((hi << 4) | lo)
}

fn parse_hex_u16(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let hi = parse_hex_u8(&bytes[0..2])? as u16;
    let lo = parse_hex_u8(&bytes[2..4])? as u16;
    Ok((hi << 8) | lo)
}

fn parse_hex_u32(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    let hi = parse_hex_u16(&bytes[0..4])? as u32;
    let lo = parse_hex_u16(&bytes[4..8])? as u32;
    Ok((hi << 16) | lo)
}

// ── Variable attributes ──────────────────────────────────────────────────────

/// EFI variable attribute flags.
///
/// These flags control when and how a variable can be accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiVarAttributes(pub u32);

impl EfiVarAttributes {
    /// Variable is stored in non-volatile storage.
    pub const NON_VOLATILE: Self = Self(0x0000_0001);
    /// Variable is accessible during boot services.
    pub const BOOTSERVICE_ACCESS: Self = Self(0x0000_0002);
    /// Variable is accessible at runtime.
    pub const RUNTIME_ACCESS: Self = Self(0x0000_0004);
    /// Hardware error record.
    pub const HARDWARE_ERROR_RECORD: Self = Self(0x0000_0008);
    /// Authenticated write access (deprecated).
    pub const AUTHENTICATED_WRITE: Self = Self(0x0000_0010);
    /// Time-based authenticated write.
    pub const TIME_BASED_AUTH_WRITE: Self = Self(0x0000_0020);
    /// Append write.
    pub const APPEND_WRITE: Self = Self(0x0000_0040);

    /// Default attributes for a standard runtime variable.
    pub const DEFAULT_NV_BS_RT: Self =
        Self(Self::NON_VOLATILE.0 | Self::BOOTSERVICE_ACCESS.0 | Self::RUNTIME_ACCESS.0);

    /// Check if the non-volatile flag is set.
    pub fn is_non_volatile(self) -> bool {
        self.0 & Self::NON_VOLATILE.0 != 0
    }

    /// Check if runtime access is allowed.
    pub fn is_runtime_access(self) -> bool {
        self.0 & Self::RUNTIME_ACCESS.0 != 0
    }

    /// Check if append-write is set.
    pub fn is_append_write(self) -> bool {
        self.0 & Self::APPEND_WRITE.0 != 0
    }
}

// ── EFI variable ─────────────────────────────────────────────────────────────

/// An EFI variable stored in the filesystem.
#[derive(Debug, Clone)]
pub struct EfiVariable {
    /// Variable name (UTF-8).
    pub name: String,
    /// Vendor GUID.
    pub vendor: EfiGuid,
    /// Variable attributes.
    pub attributes: EfiVarAttributes,
    /// Variable data.
    pub data: Vec<u8>,
    /// Whether this variable is immutable (cannot be deleted/overwritten).
    pub immutable: bool,
}

impl EfiVariable {
    /// Create a new variable.
    pub fn new(
        name: &str,
        vendor: EfiGuid,
        attributes: EfiVarAttributes,
        data: &[u8],
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_VAR_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_VAR_DATA_SIZE {
            return Err(Error::OutOfMemory);
        }
        Ok(Self {
            name: String::from(name),
            vendor,
            attributes,
            data: Vec::from(data),
            immutable: false,
        })
    }

    /// Full filename: `<name>-<guid>`.
    pub fn filename(&self) -> String {
        let mut s = self.name.clone();
        s.push('-');
        s.push_str(&self.vendor.to_string());
        s
    }

    /// File content: 4-byte LE attributes prefix + data.
    pub fn file_content(&self) -> Vec<u8> {
        let mut content = Vec::with_capacity(ATTR_PREFIX_SIZE + self.data.len());
        content.extend_from_slice(&self.attributes.0.to_le_bytes());
        content.extend_from_slice(&self.data);
        content
    }

    /// Parse file content back into attributes + data.
    pub fn parse_file_content(content: &[u8]) -> Result<(EfiVarAttributes, Vec<u8>)> {
        if content.len() < ATTR_PREFIX_SIZE {
            return Err(Error::InvalidArgument);
        }
        let attr_bytes: [u8; 4] = [content[0], content[1], content[2], content[3]];
        let attributes = EfiVarAttributes(u32::from_le_bytes(attr_bytes));
        let data = Vec::from(&content[ATTR_PREFIX_SIZE..]);
        Ok((attributes, data))
    }

    /// Total size including attribute prefix.
    pub fn total_size(&self) -> usize {
        ATTR_PREFIX_SIZE + self.data.len()
    }
}

// ── Well-known immutable variables ───────────────────────────────────────────

/// Names of variables that should be treated as immutable.
const IMMUTABLE_VARS: &[&str] = &["SecureBoot", "PK", "KEK", "SetupMode", "AuditMode"];

/// Check if a variable name is in the immutable list.
fn is_immutable_var(name: &str) -> bool {
    IMMUTABLE_VARS.iter().any(|&v| v == name)
}

// ── efivarfs inode ───────────────────────────────────────────────────────────

/// efivarfs inode metadata.
#[derive(Debug, Clone)]
pub struct EfivarfsInode {
    /// Inode number.
    pub ino: u64,
    /// File type (Regular for variables, Directory for root).
    pub file_type: FileType,
    /// Permission bits.
    pub mode: u16,
    /// File size in bytes (attributes prefix + data).
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Associated variable name (empty for root directory).
    pub var_name: String,
}

impl EfivarfsInode {
    /// Create a root directory inode.
    fn root() -> Self {
        Self {
            ino: 1,
            file_type: FileType::Directory,
            mode: 0o755,
            size: 0,
            nlink: 2,
            var_name: String::new(),
        }
    }

    /// Create a variable file inode.
    fn variable(ino: u64, var: &EfiVariable) -> Self {
        let mode = if var.immutable { 0o444 } else { 0o644 };
        Self {
            ino,
            file_type: FileType::Regular,
            mode,
            size: var.total_size() as u64,
            nlink: 1,
            var_name: var.name.clone(),
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = self.size;
        vfs.nlink = self.nlink;
        vfs
    }
}

// ── Directory entry ──────────────────────────────────────────────────────────

/// In-memory directory entry (always in the root directory).
#[derive(Debug, Clone)]
struct EfivarfsDirEntry {
    /// Target inode number.
    ino: u64,
    /// Filename (`<name>-<guid>`).
    filename: String,
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted efivarfs filesystem handle.
///
/// Provides a virtual filesystem where each EFI variable appears as a
/// regular file in a flat root directory.
pub struct EfivarfsFs {
    /// Inode table.
    inodes: Vec<EfivarfsInode>,
    /// Directory entries (all in the root directory).
    dir_entries: Vec<EfivarfsDirEntry>,
    /// Variable storage.
    variables: Vec<EfiVariable>,
    /// Next inode number.
    next_ino: u64,
    /// Total storage space consumed by all variables.
    total_used: usize,
    /// Maximum total storage (simulated firmware limit).
    max_storage: usize,
}

impl EfivarfsFs {
    /// Create a new efivarfs filesystem.
    ///
    /// `max_storage` is the simulated firmware variable storage limit.
    pub fn new(max_storage: usize) -> Self {
        let root = EfivarfsInode::root();
        Self {
            inodes: alloc::vec![root],
            dir_entries: Vec::new(),
            variables: Vec::new(),
            next_ino: 2,
            total_used: 0,
            max_storage,
        }
    }

    /// Create a new filesystem with the default 256 KiB storage limit.
    pub fn with_default_storage() -> Self {
        Self::new(256 * 1024)
    }

    /// Remaining storage space.
    pub fn remaining_storage(&self) -> usize {
        self.max_storage.saturating_sub(self.total_used)
    }

    /// Number of variables stored.
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    // ── Variable CRUD operations ─────────────────────────────────────

    /// Set (create or update) an EFI variable.
    pub fn set_variable(
        &mut self,
        name: &str,
        vendor: EfiGuid,
        attributes: EfiVarAttributes,
        data: &[u8],
    ) -> Result<()> {
        let filename = format_var_filename(name, &vendor);

        // Check if variable already exists.
        if let Some(existing) = self.variables.iter().find(|v| v.filename() == filename) {
            if existing.immutable {
                return Err(Error::PermissionDenied);
            }
        }

        // Size check.
        let new_size = ATTR_PREFIX_SIZE + data.len();
        let old_size = self
            .variables
            .iter()
            .find(|v| v.filename() == filename)
            .map(|v| v.total_size())
            .unwrap_or(0);
        let delta = new_size as isize - old_size as isize;
        if delta > 0 && self.total_used + delta as usize > self.max_storage {
            return Err(Error::OutOfMemory);
        }

        let mut var = EfiVariable::new(name, vendor, attributes, data)?;
        if is_immutable_var(name) {
            var.immutable = true;
        }

        // Remove old version if exists.
        let fn_clone = filename.clone();
        if let Some(pos) = self.variables.iter().position(|v| v.filename() == fn_clone) {
            self.total_used -= self.variables[pos].total_size();
            self.variables.remove(pos);
            // Remove old directory entry and inode.
            if let Some(de_pos) = self
                .dir_entries
                .iter()
                .position(|de| de.filename == fn_clone)
            {
                let old_ino = self.dir_entries[de_pos].ino;
                self.dir_entries.remove(de_pos);
                self.inodes.retain(|i| i.ino != old_ino);
            }
        }

        // Add new version.
        if self.variables.len() >= MAX_VARIABLES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.next_ino;
        self.next_ino += 1;

        let inode = EfivarfsInode::variable(ino, &var);
        self.inodes.push(inode);
        self.dir_entries.push(EfivarfsDirEntry {
            ino,
            filename: filename.clone(),
        });
        self.total_used += var.total_size();
        self.variables.push(var);

        Ok(())
    }

    /// Get an EFI variable by name and vendor GUID.
    pub fn get_variable(&self, name: &str, vendor: &EfiGuid) -> Result<&EfiVariable> {
        let filename = format_var_filename(name, vendor);
        self.variables
            .iter()
            .find(|v| v.filename() == filename)
            .ok_or(Error::NotFound)
    }

    /// Delete an EFI variable.
    pub fn delete_variable(&mut self, name: &str, vendor: &EfiGuid) -> Result<()> {
        let filename = format_var_filename(name, vendor);
        let pos = self
            .variables
            .iter()
            .position(|v| v.filename() == filename)
            .ok_or(Error::NotFound)?;

        if self.variables[pos].immutable {
            return Err(Error::PermissionDenied);
        }

        self.total_used -= self.variables[pos].total_size();
        self.variables.remove(pos);

        // Remove directory entry and inode.
        if let Some(de_pos) = self
            .dir_entries
            .iter()
            .position(|de| de.filename == filename)
        {
            let old_ino = self.dir_entries[de_pos].ino;
            self.dir_entries.remove(de_pos);
            self.inodes.retain(|i| i.ino != old_ino);
        }
        Ok(())
    }

    /// List all variable names.
    pub fn list_variables(&self) -> Vec<String> {
        self.variables.iter().map(|v| v.filename()).collect()
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&EfivarfsInode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Find a directory entry by filename.
    fn find_dir_entry(&self, filename: &str) -> Result<&EfivarfsDirEntry> {
        self.dir_entries
            .iter()
            .find(|de| de.filename == filename)
            .ok_or(Error::NotFound)
    }

    /// Find a variable by inode number.
    fn find_variable_by_ino(&self, ino: u64) -> Result<&EfiVariable> {
        let de = self
            .dir_entries
            .iter()
            .find(|de| de.ino == ino)
            .ok_or(Error::NotFound)?;
        self.variables
            .iter()
            .find(|v| v.filename() == de.filename)
            .ok_or(Error::NotFound)
    }
}

/// Format a variable filename: `<name>-<guid>`.
fn format_var_filename(name: &str, vendor: &EfiGuid) -> String {
    let mut s = String::from(name);
    s.push('-');
    s.push_str(&vendor.to_string());
    s
}

// ── InodeOps implementation ──────────────────────────────────────────────────

impl InodeOps for EfivarfsFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        // All entries are in the root directory.
        if parent.ino.0 != 1 {
            return Err(Error::NotFound);
        }
        let de = self.find_dir_entry(name)?;
        let inode = self.find_inode(de.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, parent: &Inode, name: &str, _mode: FileMode) -> Result<Inode> {
        // Creating files directly is not supported — use set_variable().
        if parent.ino.0 != 1 {
            return Err(Error::InvalidArgument);
        }
        if name.is_empty() || name.len() > MAX_VAR_NAME_LEN + GUID_STRING_LEN + 1 {
            return Err(Error::InvalidArgument);
        }
        // Parse name-guid format.
        let dash_pos = name.rfind('-').ok_or(Error::InvalidArgument)?;
        // Verify there's a GUID portion.
        if name.len() - dash_pos - 1 < GUID_STRING_LEN {
            return Err(Error::InvalidArgument);
        }
        // Create an empty variable through the variable interface.
        let var_name = &name[..dash_pos - GUID_STRING_LEN + 1];
        let guid_str = &name[name.len() - GUID_STRING_LEN..];
        let vendor = EfiGuid::from_string(guid_str)?;
        self.set_variable(var_name, vendor, EfiVarAttributes::DEFAULT_NV_BS_RT, &[])?;
        // Find the created inode.
        let de = self.find_dir_entry(name)?;
        let inode = self.find_inode(de.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn mkdir(&mut self, _parent: &Inode, _name: &str, _mode: FileMode) -> Result<Inode> {
        // Subdirectories are not supported in efivarfs.
        Err(Error::NotImplemented)
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        if parent.ino.0 != 1 {
            return Err(Error::NotFound);
        }
        let de = self.find_dir_entry(name)?;
        let var = self.find_variable_by_ino(de.ino)?;
        if var.immutable {
            return Err(Error::PermissionDenied);
        }
        let vendor = var.vendor;
        let var_name = var.name.clone();
        self.delete_variable(&var_name, &vendor)
    }

    fn rmdir(&mut self, _parent: &Inode, _name: &str) -> Result<()> {
        // No subdirectories.
        Err(Error::NotImplemented)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let efi_inode = self.find_inode(inode.ino.0)?;
        if efi_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let var = self.find_variable_by_ino(inode.ino.0)?;
        let content = var.file_content();
        let start = offset as usize;
        if start >= content.len() {
            return Ok(0);
        }
        let available = content.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&content[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let efi_inode = self.find_inode(inode.ino.0)?;
        if efi_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let ino = inode.ino.0;

        // Find the variable and check immutability.
        let de_filename = self
            .dir_entries
            .iter()
            .find(|de| de.ino == ino)
            .map(|de| de.filename.clone())
            .ok_or(Error::NotFound)?;
        let var_idx = self
            .variables
            .iter()
            .position(|v| v.filename() == de_filename)
            .ok_or(Error::NotFound)?;

        if self.variables[var_idx].immutable {
            return Err(Error::PermissionDenied);
        }

        // Writing replaces the entire content (attributes + data).
        // Must start at offset 0 for a full replace.
        if offset != 0 {
            return Err(Error::InvalidArgument);
        }
        if data.len() < ATTR_PREFIX_SIZE {
            return Err(Error::InvalidArgument);
        }
        let (new_attrs, new_data) = EfiVariable::parse_file_content(data)?;

        let old_size = self.variables[var_idx].total_size();
        let new_size = ATTR_PREFIX_SIZE + new_data.len();
        if self.total_used - old_size + new_size > self.max_storage {
            return Err(Error::OutOfMemory);
        }

        self.total_used = self.total_used - old_size + new_size;
        self.variables[var_idx].attributes = new_attrs;
        self.variables[var_idx].data = new_data;

        // Update inode size.
        if let Some(inode_mut) = self.inodes.iter_mut().find(|i| i.ino == ino) {
            inode_mut.size = new_size as u64;
        }

        Ok(data.len())
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let efi_inode = self.find_inode(inode.ino.0)?;
        if efi_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        // Truncating to zero means deleting the variable content.
        if size == 0 {
            let ino = inode.ino.0;
            let de_filename = self
                .dir_entries
                .iter()
                .find(|de| de.ino == ino)
                .map(|de| de.filename.clone())
                .ok_or(Error::NotFound)?;
            if let Some(var) = self
                .variables
                .iter_mut()
                .find(|v| v.filename() == de_filename)
            {
                if var.immutable {
                    return Err(Error::PermissionDenied);
                }
                self.total_used -= var.data.len();
                var.data.clear();
            }
            if let Some(inode_mut) = self.inodes.iter_mut().find(|i| i.ino == ino) {
                inode_mut.size = ATTR_PREFIX_SIZE as u64;
            }
            return Ok(());
        }
        // Arbitrary truncation is not meaningful for EFI variables.
        Err(Error::NotImplemented)
    }
}
