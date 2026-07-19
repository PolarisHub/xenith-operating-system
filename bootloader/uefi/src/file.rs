//! UEFI Simple File System access without an allocator.

use core::ffi::c_void;

use crate::abi::{
    is_error, BootServices, FileProtocol, Guid, Handle, LoadedImageProtocol,
    SimpleFileSystemProtocol, ALLOCATE_MAX_ADDRESS, FILE_INFO_GUID, FILE_MODE_READ,
    LOADED_IMAGE_GUID, LOADER_DATA, SIMPLE_FILE_SYSTEM_GUID,
};
use crate::LoaderError;

#[derive(Clone, Copy)]
pub struct LoadedFile {
    pub address: u64,
    pub byte_len: usize,
}

impl LoadedFile {
    /// The firmware allocation is identity-addressed until Xenith installs its own tables.
    pub unsafe fn bytes<'a>(self) -> &'a [u8] {
        // SAFETY: the allocation remains loader-owned for the entire handoff.
        unsafe { core::slice::from_raw_parts(self.address as *const u8, self.byte_len) }
    }
}

pub unsafe fn open_root(
    boot_services: &BootServices,
    image_handle: Handle,
) -> Result<*mut FileProtocol, LoaderError> {
    let mut loaded_image = core::ptr::null_mut::<c_void>();
    // SAFETY: firmware owns both protocol databases and validates the image handle.
    let status = unsafe {
        (boot_services.handle_protocol)(image_handle, &LOADED_IMAGE_GUID, &mut loaded_image)
    };
    if is_error(status) || loaded_image.is_null() {
        return Err(LoaderError::Protocol(status));
    }
    // SAFETY: successful HandleProtocol returned the requested interface type.
    let loaded_image = unsafe { &*(loaded_image.cast::<LoadedImageProtocol>()) };
    let mut filesystem = core::ptr::null_mut::<c_void>();
    // SAFETY: the loaded image's device handle is firmware-provided and live.
    let status = unsafe {
        (boot_services.handle_protocol)(
            loaded_image.device_handle,
            &SIMPLE_FILE_SYSTEM_GUID,
            &mut filesystem,
        )
    };
    if is_error(status) || filesystem.is_null() {
        return Err(LoaderError::Protocol(status));
    }
    let filesystem = filesystem.cast::<SimpleFileSystemProtocol>();
    let mut root = core::ptr::null_mut();
    // SAFETY: successful protocol lookup establishes the open-volume vtable.
    let status = unsafe { ((*filesystem).open_volume)(filesystem, &mut root) };
    if is_error(status) || root.is_null() {
        Err(LoaderError::File(status))
    } else {
        Ok(root)
    }
}

pub unsafe fn load_file(
    boot_services: &BootServices,
    root: *mut FileProtocol,
    ascii_path: &[u8],
) -> Result<LoadedFile, LoaderError> {
    let mut path = [0_u16; 96];
    if ascii_path.len() + 1 > path.len() {
        return Err(LoaderError::Path);
    }
    for (destination, source) in path.iter_mut().zip(ascii_path.iter().copied()) {
        *destination = u16::from(source);
    }
    let mut file = core::ptr::null_mut();
    // SAFETY: root is a live directory protocol and `path` is NUL-terminated UTF-16.
    let status = unsafe { ((*root).open)(root, &mut file, path.as_ptr(), FILE_MODE_READ, 0) };
    if is_error(status) || file.is_null() {
        return Err(LoaderError::File(status));
    }
    let result = unsafe { read_open_file(boot_services, file) };
    // SAFETY: the file handle is live even when reading or allocation failed.
    let _ = unsafe { ((*file).close)(file) };
    result
}

unsafe fn read_open_file(
    boot_services: &BootServices,
    file: *mut FileProtocol,
) -> Result<LoadedFile, LoaderError> {
    let mut info = [0_u64; 64];
    let mut info_size = core::mem::size_of_val(&info);
    // SAFETY: `info` is aligned and large enough for short paths used by this loader.
    let status = unsafe {
        ((*file).get_info)(
            file,
            &FILE_INFO_GUID as *const Guid,
            &mut info_size,
            info.as_mut_ptr().cast::<c_void>(),
        )
    };
    if is_error(status) {
        return Err(LoaderError::FileInfo(status));
    }
    let byte_len = usize::try_from(info[1]).map_err(|_| LoaderError::FileSize)?;
    if byte_len == 0 {
        return Err(LoaderError::FileSize);
    }
    let pages = byte_len.checked_add(4095).ok_or(LoaderError::FileSize)? / 4096;
    let mut address = u64::from(u32::MAX);
    // SAFETY: allocation is below 4 GiB so the transitional identity map covers it.
    let status = unsafe {
        (boot_services.allocate_pages)(ALLOCATE_MAX_ADDRESS, LOADER_DATA, pages, &mut address)
    };
    if is_error(status) {
        return Err(LoaderError::Allocation(status));
    }
    let mut read_size = byte_len;
    // SAFETY: the firmware owns `file`; the allocation covers `byte_len` writable bytes.
    let status = unsafe { ((*file).read)(file, &mut read_size, address as usize as *mut c_void) };
    if is_error(status) || read_size != byte_len {
        // SAFETY: this exact allocation was created above and is not exposed on failure.
        let _ = unsafe { (boot_services.free_pages)(address, pages) };
        return Err(LoaderError::File(status));
    }
    Ok(LoadedFile { address, byte_len })
}
