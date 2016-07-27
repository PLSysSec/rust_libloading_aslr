extern crate winapi;
extern crate kernel32;

use util::{CowCString, CStringAsRef};

use std::ffi::{OsStr, OsString};
use std::{fmt, io, marker, mem, ptr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT, Ordering};


/// A platform-specific equivalent of the cross-platform `Library`.
pub struct Library(winapi::HMODULE);

// There’s little documentation on Send-ability of HMODULE, but lack of warnings on the MSDN page
// and reading http://stackoverflow.com/a/11254061, it seems like it should be fine?
unsafe impl ::std::marker::Send for Library {}

impl Library {
    /// Find and load a shared library (module).
    ///
    /// Locations where library is searched for is platform specific and can’t be adjusted
    /// portably.
    ///
    /// Corresponds to `LoadLibraryW(filename)`.
    #[inline]
    pub fn new<P: AsRef<OsStr>>(filename: P) -> ::Result<Library> {
        let wide_filename: Vec<u16> = filename.as_ref().encode_wide().chain(Some(0)).collect();
        let _guard = ErrorModeGuard::new();

        let ret = with_get_last_error(|| {
            // Make sure no winapi calls as a result of drop happen inside this closure, because
            // otherwise that might change the return value of the GetLastError.
            let handle = unsafe { kernel32::LoadLibraryW(wide_filename.as_ptr()) };
            if handle.is_null()  {
                None
            } else {
                Some(Library(handle))
            }
        }).map_err(|e| e.unwrap_or_else(||
            panic!("LoadLibraryW failed but GetLastError did not report the error")
        ));

        drop(wide_filename); // Drop wide_filename here to ensure it doesn’t get moved and dropped
                             // inside the closure by mistake. See comment inside the closure.
        ret
    }

    /// Get a pointer to function or static variable by symbol name.
    ///
    /// The `symbol` may not contain any null bytes, with an exception of last byte. A null
    /// terminated `symbol` may avoid a string allocation in some cases.
    ///
    /// Symbol is interpreted as-is; no mangling is done. This means that symbols like `x::y` are
    /// most likely invalid.
    ///
    /// # Unsafety
    ///
    /// Pointer to a value of arbitrary type is returned. Using a value with wrong type is
    /// undefined.
    pub unsafe fn get<T>(&self, symbol: &[u8]) -> ::Result<Symbol<T>> {
        let symbol = try!(CowCString::from_bytes(symbol));
        with_get_last_error(|| {
            let symbol = kernel32::GetProcAddress(self.0, symbol.cstring_ref());
            if symbol.is_null() {
                None
            } else {
                Some(Symbol {
                    pointer: symbol,
                    pd: marker::PhantomData
                })
            }
        }).map_err(|e| e.unwrap_or_else(||
            panic!("GetProcAddress failed but GetLastError did not report the error")
        ))
    }

    /// Get a pointer to function or static variable by ordinal number.
    pub unsafe fn get_ordinal<T>(&self, ordinal: winapi::WORD) -> ::Result<Symbol<T>> {
        with_get_last_error(|| {
            let ordinal = ordinal as usize as *mut _;
            let symbol = kernel32::GetProcAddress(self.0, ordinal);
            if symbol.is_null() {
                None
            } else {
                Some(Symbol {
                    pointer: symbol,
                    pd: marker::PhantomData
                })
            }
        }).map_err(|e| e.unwrap_or_else(||
            panic!("GetProcAddress failed but GetLastError did not report the error")
        ))
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        with_get_last_error(|| {
            if unsafe { kernel32::FreeLibrary(self.0) == 0 } {
                None
            } else {
                Some(())
            }
        }).unwrap()
    }
}

impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mut buf: [winapi::WCHAR; 1024] = mem::uninitialized();
            let len = kernel32::GetModuleFileNameW(self.0,
                                                   (&mut buf[..]).as_mut_ptr(), 1024) as usize;
            if len == 0 {
                f.write_str(&format!("Library@{:p}", self.0))
            } else {
                let string: OsString = OsString::from_wide(&buf[..len]);
                f.write_str(&format!("Library@{:p} from {:?}", self.0, string))
            }
        }
    }
}

/// Symbol from a library.
///
/// A major difference compared to the cross-platform `Symbol` is that this does not ensure the
/// `Symbol` does not outlive `Library` it comes from.
#[derive(Clone)]
pub struct Symbol<T> {
    pointer: winapi::FARPROC,
    pd: marker::PhantomData<T>
}

impl<T> ::std::ops::Deref for Symbol<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            // Additional reference level for a dereference on `deref` return value.
            mem::transmute(&self.pointer)
        }
    }
}

impl<T> fmt::Debug for Symbol<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("Symbol@{:p}", self.pointer))
    }
}


static USE_ERRORMODE: AtomicBool = ATOMIC_BOOL_INIT;
struct ErrorModeGuard(winapi::DWORD);

impl ErrorModeGuard {
    fn new() -> ErrorModeGuard {
        let mut ret = ErrorModeGuard(0);

        if !USE_ERRORMODE.load(Ordering::Acquire) {
            if unsafe { kernel32::SetThreadErrorMode(1, &mut ret.0) == 0
                        && kernel32::GetLastError() == winapi::ERROR_CALL_NOT_IMPLEMENTED } {
                USE_ERRORMODE.store(true, Ordering::Release);
            } else {
                return ret;
            }
        }
        ret.0 = unsafe { kernel32::SetErrorMode(1) };
        ret
    }
}

impl Drop for ErrorModeGuard {
    fn drop(&mut self) {
        unsafe {
            if !USE_ERRORMODE.load(Ordering::Relaxed) {
                kernel32::SetThreadErrorMode(self.0, ptr::null_mut());
            } else {
                kernel32::SetErrorMode(self.0);
            }
        }
    }
}

fn with_get_last_error<T, F>(closure: F) -> Result<T, Option<io::Error>>
where F: FnOnce() -> Option<T> {
    closure().ok_or_else(|| {
        let error = unsafe { kernel32::GetLastError() };
        if error == 0 {
            None
        } else {
            Some(io::Error::from_raw_os_error(error as i32))
        }
    })
}

#[test]
fn works_getlasterror() {
    let lib = Library::new("kernel32.dll").unwrap();
    let gle: Symbol<unsafe extern "system" fn() -> winapi::DWORD> = unsafe {
        lib.get(b"GetLastError").unwrap()
    };
    unsafe {
        kernel32::SetLastError(42);
        assert_eq!(kernel32::GetLastError(), gle())
    }
}

#[test]
fn works_getlasterror0() {
    let lib = Library::new("kernel32.dll").unwrap();
    let gle: Symbol<unsafe extern "system" fn() -> winapi::DWORD> = unsafe {
        lib.get(b"GetLastError\0").unwrap()
    };
    unsafe {
        kernel32::SetLastError(42);
        assert_eq!(kernel32::GetLastError(), gle())
    }
}

#[test]
fn fails_new_kernel23() {
    Library::new("kernel23").err().unwrap();
}
