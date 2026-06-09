use std::io;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::mem;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::time::Duration;

    // Compile-time size assertions
    const _: () = assert!(mem::size_of::<NlMsgHdr>() == 16);
    const _: () = assert!(mem::size_of::<NfGenMsg>() == 4);
    const _: () = assert!(mem::size_of::<NlAttr>() == 4);

    pub const NETLINK_NETFILTER: i32 = 12;
    pub const AF_NETLINK: i32 = libc::AF_NETLINK;

    pub const NLM_F_REQUEST: u16 = 0x01;
    pub const NLM_F_ACK: u16 = 0x04;
    pub const NLM_F_CREATE: u16 = 0x400;

    pub const NLMSG_ERROR: u16 = 0x02;
    pub const NLMSG_DONE: u16 = 0x03;
    pub const NLMSG_MIN_TYPE: u16 = 0x10;

    pub const NLA_F_NESTED: u16 = 1 << 15;

    pub const NFNL_SUBSYS_NFTABLES: u8 = 10;

    pub const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE;
    pub const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE + 1;

    pub const NLA_ALIGNTO: usize = 4;

    #[inline]
    pub fn nla_align(len: usize) -> usize {
        (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct NlMsgHdr {
        pub nlmsg_len: u32,
        pub nlmsg_type: u16,
        pub nlmsg_flags: u16,
        pub nlmsg_seq: u32,
        pub nlmsg_pid: u32,
    }

    impl NlMsgHdr {
        pub const SIZE: usize = mem::size_of::<NlMsgHdr>();
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct NfGenMsg {
        pub nfgen_family: u8,
        pub version: u8,
        pub res_id: u16, // Network byte order
    }

    impl NfGenMsg {
        pub const SIZE: usize = mem::size_of::<NfGenMsg>();
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct NlAttr {
        pub nla_len: u16,
        pub nla_type: u16,
    }

    impl NlAttr {
        pub const SIZE: usize = mem::size_of::<NlAttr>();
    }

    pub struct NetlinkSocket {
        fd: RawFd,
    }

    impl NetlinkSocket {
        pub fn new() -> io::Result<Self> {
            let fd = unsafe {
                libc::socket(
                    AF_NETLINK,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    NETLINK_NETFILTER,
                )
            };

            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
            addr.nl_family = AF_NETLINK as u16;
            addr.nl_pid = 0;
            addr.nl_groups = 0;

            let ret = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_nl>() as u32,
                )
            };

            if ret < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            Ok(Self { fd })
        }

        pub fn send(&self, msg: &[u8]) -> io::Result<()> {
            let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
            addr.nl_family = AF_NETLINK as u16;
            addr.nl_pid = 0;
            addr.nl_groups = 0;

            let sent = unsafe {
                libc::sendto(
                    self.fd,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_nl>() as u32,
                )
            };

            if sent < 0 {
                return Err(io::Error::last_os_error());
            }

            if sent as usize != msg.len() {
                return Err(io::Error::other("incomplete send"));
            }

            Ok(())
        }

        pub fn recv(&self, recv_buf: &mut [u8]) -> io::Result<usize> {
            let mut retries = 3;
            loop {
                let received = unsafe {
                    libc::recv(
                        self.fd,
                        recv_buf.as_mut_ptr() as *mut libc::c_void,
                        recv_buf.len(),
                        0,
                    )
                };

                if received < 0 {
                    let err = io::Error::last_os_error();
                    if retries > 0
                        && (err.raw_os_error() == Some(libc::EAGAIN)
                            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                            || err.raw_os_error() == Some(libc::EINTR))
                    {
                        retries -= 1;
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    return Err(err);
                }

                return Ok(received as usize);
            }
        }
    }

    impl AsRawFd for NetlinkSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    impl Drop for NetlinkSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    pub struct MsgBuffer {
        data: Vec<u8>,
    }

    #[allow(dead_code)]
    impl MsgBuffer {
        pub fn new(capacity: usize) -> Self {
            Self {
                data: Vec::with_capacity(capacity),
            }
        }

        pub fn len(&self) -> usize {
            self.data.len()
        }

        pub fn as_slice(&self) -> &[u8] {
            &self.data
        }

        pub fn put_bytes(&mut self, bytes: &[u8]) {
            self.data.extend_from_slice(bytes);
        }

        pub fn put_u8(&mut self, val: u8) {
            self.data.push(val);
        }

        pub fn put_u16(&mut self, val: u16) {
            self.data.extend_from_slice(&val.to_ne_bytes());
        }

        pub fn put_u32(&mut self, val: u32) {
            self.data.extend_from_slice(&val.to_ne_bytes());
        }

        pub fn put_u32_be(&mut self, val: u32) {
            self.data.extend_from_slice(&val.to_be_bytes());
        }

        pub fn put_u64_be(&mut self, val: u64) {
            self.data.extend_from_slice(&val.to_be_bytes());
        }

        pub fn align(&mut self) {
            let aligned = nla_align(self.data.len());
            self.data.resize(aligned, 0);
        }

        pub fn put_nlmsghdr(&mut self, msg_type: u16, flags: u16, seq: u32) {
            let hdr = NlMsgHdr {
                nlmsg_len: 0, // Will be updated later
                nlmsg_type: msg_type,
                nlmsg_flags: flags,
                nlmsg_seq: seq,
                nlmsg_pid: 0,
            };
            let bytes: [u8; NlMsgHdr::SIZE] = unsafe { mem::transmute(hdr) };
            self.put_bytes(&bytes);
        }

        pub fn put_nfgenmsg(&mut self, family: u8, version: u8, res_id: u16) {
            let msg = NfGenMsg {
                nfgen_family: family,
                version,
                res_id: res_id.to_be(),
            };
            let bytes: [u8; NfGenMsg::SIZE] = unsafe { mem::transmute(msg) };
            self.put_bytes(&bytes);
        }

        pub fn put_attr_str(&mut self, attr_type: u16, val: &str) {
            let bytes = val.as_bytes();
            let len = NlAttr::SIZE + bytes.len() + 1; // +1 for null terminator
            self.put_u16(len as u16);
            self.put_u16(attr_type);
            self.put_bytes(bytes);
            self.put_u8(0); // Null terminator
            self.align();
        }

        pub fn put_attr_bytes(&mut self, attr_type: u16, val: &[u8]) {
            let len = NlAttr::SIZE + val.len();
            self.put_u16(len as u16);
            self.put_u16(attr_type);
            self.put_bytes(val);
            self.align();
        }

        pub fn put_attr_u32_nft(&mut self, attr_type: u16, val: u32) {
            let len = NlAttr::SIZE + 4;
            self.put_u16(len as u16);
            self.put_u16(attr_type);
            self.put_u32_be(val);
            self.align();
        }

        pub fn put_attr_u64_nft(&mut self, attr_type: u16, val: u64) {
            let len = NlAttr::SIZE + 8;
            self.put_u16(len as u16);
            self.put_u16(attr_type);
            self.put_u64_be(val);
            self.align();
        }

        pub fn start_nested(&mut self, attr_type: u16) -> usize {
            let offset = self.data.len();
            self.put_u16(0); // Placeholder for length
            self.put_u16(attr_type | NLA_F_NESTED);
            offset
        }

        pub fn end_nested(&mut self, offset: usize) {
            let len = (self.data.len() - offset) as u16;
            self.data[offset..offset + 2].copy_from_slice(&len.to_ne_bytes());
        }

        pub fn finalize_nlmsg(&mut self) {
            let len = self.data.len() as u32;
            self.data[0..4].copy_from_slice(&len.to_ne_bytes());
        }

        pub fn finalize_nlmsg_at(&mut self, offset: usize) {
            let len = (self.data.len() - offset) as u32;
            self.data[offset..offset + 4].copy_from_slice(&len.to_ne_bytes());
        }
    }

    pub fn parse_nlmsg_error(buf: &[u8]) -> Option<i32> {
        if buf.len() < NlMsgHdr::SIZE {
            return None;
        }
        let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
        if hdr.nlmsg_type != NLMSG_ERROR {
            return None;
        }
        if buf.len() < NlMsgHdr::SIZE + 4 {
            return None;
        }
        let error: i32 =
            unsafe { std::ptr::read_unaligned(buf[NlMsgHdr::SIZE..].as_ptr() as *const i32) };
        Some(error)
    }

    pub fn is_nlmsg_done(buf: &[u8]) -> bool {
        if buf.len() < NlMsgHdr::SIZE {
            return false;
        }
        let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
        hdr.nlmsg_type == NLMSG_DONE
    }

    pub fn get_nlmsg_type(buf: &[u8]) -> Option<u16> {
        if buf.len() < NlMsgHdr::SIZE {
            return None;
        }
        let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const NlMsgHdr) };
        Some(hdr.nlmsg_type)
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
mod non_linux_impl {
    use super::*;

    pub const NLM_F_REQUEST: u16 = 0x01;
    pub const NLM_F_ACK: u16 = 0x04;
    pub const NLM_F_CREATE: u16 = 0x400;

    pub const NLMSG_ERROR: u16 = 0x02;
    pub const NLMSG_DONE: u16 = 0x03;
    pub const NLMSG_MIN_TYPE: u16 = 0x10;

    pub const NLA_F_NESTED: u16 = 1 << 15;

    pub const NFNL_SUBSYS_NFTABLES: u8 = 10;

    pub const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE;
    pub const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE + 1;

    pub struct NetlinkSocket;

    impl NetlinkSocket {
        pub fn new() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Netlink is only supported on Linux",
            ))
        }

        pub fn send(&self, _msg: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Netlink is only supported on Linux",
            ))
        }

        pub fn recv(&self, _recv_buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Netlink is only supported on Linux",
            ))
        }
    }

    pub struct MsgBuffer;

    #[allow(dead_code)]
    impl MsgBuffer {
        pub fn new(_capacity: usize) -> Self {
            Self
        }
        pub fn len(&self) -> usize {
            0
        }
        pub fn as_slice(&self) -> &[u8] {
            &[]
        }
        pub fn put_bytes(&mut self, _bytes: &[u8]) {}
        pub fn put_u8(&mut self, _val: u8) {}
        pub fn put_u16(&mut self, _val: u16) {}
        pub fn put_u32(&mut self, _val: u32) {}
        pub fn put_u32_be(&mut self, _val: u32) {}
        pub fn put_u64_be(&mut self, _val: u64) {}
        pub fn align(&mut self) {}
        pub fn put_nlmsghdr(&mut self, _msg_type: u16, _flags: u16, _seq: u32) {}
        pub fn put_nfgenmsg(&mut self, _family: u8, _version: u8, _res_id: u16) {}
        pub fn put_attr_str(&mut self, _attr_type: u16, _val: &str) {}
        pub fn put_attr_bytes(&mut self, _attr_type: u16, _val: &[u8]) {}
        pub fn put_attr_u32_nft(&mut self, _attr_type: u16, _val: u32) {}
        pub fn put_attr_u64_nft(&mut self, _attr_type: u16, _val: u64) {}
        pub fn start_nested(&mut self, _attr_type: u16) -> usize {
            0
        }
        pub fn end_nested(&mut self, _offset: usize) {}
        pub fn finalize_nlmsg(&mut self) {}
        pub fn finalize_nlmsg_at(&mut self, _offset: usize) {}
    }

    pub fn parse_nlmsg_error(_buf: &[u8]) -> Option<i32> {
        None
    }
    pub fn is_nlmsg_done(_buf: &[u8]) -> bool {
        false
    }
    pub fn get_nlmsg_type(_buf: &[u8]) -> Option<u16> {
        None
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(unused_imports)]
pub use non_linux_impl::*;
