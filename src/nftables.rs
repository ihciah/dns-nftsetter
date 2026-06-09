use std::io;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::netlink::{
        get_nlmsg_type, is_nlmsg_done, parse_nlmsg_error, MsgBuffer, NetlinkSocket,
        NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NLMSG_ERROR, NLM_F_ACK,
        NLM_F_CREATE, NLM_F_REQUEST,
    };

    const NFT_MSG_NEWSETELEM: u16 = 12;

    const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
    const NFTA_SET_ELEM_LIST_SET: u16 = 2;
    const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

    const NFTA_SET_ELEM_KEY: u16 = 1;
    const NFTA_SET_ELEM_TIMEOUT: u16 = 4;

    const NFTA_DATA_VALUE: u16 = 1;

    #[derive(Clone, Debug)]
    pub struct NftElement {
        pub key: Vec<u8>,
        pub timeout_secs: u32,
    }

    fn parse_nf_family(family: &str) -> io::Result<u8> {
        match family.to_lowercase().as_str() {
            "inet" => Ok(1),          // NFPROTO_INET
            "ip" | "ipv4" => Ok(2),   // NFPROTO_IPV4
            "ip6" | "ipv6" => Ok(10), // NFPROTO_IPV6
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported nftables family: {}", family),
            )),
        }
    }

    fn nft_msg_type(cmd: u16) -> u16 {
        ((NFNL_SUBSYS_NFTABLES as u16) << 8) | cmd
    }

    fn append_newsetelem_message(
        buf: &mut MsgBuffer,
        table: &str,
        setname: &str,
        nf_family: u8,
        elements: &[NftElement],
    ) {
        let msg_start = buf.len();
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
        buf.put_nlmsghdr(nft_msg_type(NFT_MSG_NEWSETELEM), flags, 1);
        buf.put_nfgenmsg(nf_family, 0, 0);

        buf.put_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
        buf.put_attr_str(NFTA_SET_ELEM_LIST_SET, setname);

        // Elements list (nested)
        let elems_offset = buf.start_nested(NFTA_SET_ELEM_LIST_ELEMENTS);

        for element in elements {
            // One nested element per set entry.
            let elem_offset = buf.start_nested(0);

            let key_offset = buf.start_nested(NFTA_SET_ELEM_KEY);
            buf.put_attr_bytes(NFTA_DATA_VALUE, &element.key);
            buf.end_nested(key_offset);

            if element.timeout_secs > 0 {
                buf.put_attr_u64_nft(
                    NFTA_SET_ELEM_TIMEOUT,
                    (element.timeout_secs as u64) * 1000,
                );
            }

            buf.end_nested(elem_offset);
        }

        buf.end_nested(elems_offset);
        buf.finalize_nlmsg_at(msg_start);
    }

    pub fn nftables_add_elements(
        family: &str,
        table: &str,
        setname: &str,
        elements: &[NftElement],
    ) -> io::Result<()> {
        if elements.is_empty() {
            return Ok(());
        }

        let nf_family = parse_nf_family(family)?;

        let mut buf = MsgBuffer::new(4096);

        // Batch begin message.
        buf.put_nlmsghdr(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0);
        buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
        buf.finalize_nlmsg();

        append_newsetelem_message(&mut buf, table, setname, nf_family, elements);

        // Batch end message.
        let end_start = buf.len();
        buf.put_nlmsghdr(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 2);
        buf.put_nfgenmsg(libc::AF_UNSPEC as u8, 0, NFNL_SUBSYS_NFTABLES as u16);
        buf.finalize_nlmsg_at(end_start);

        // Send to Netlink
        let socket = NetlinkSocket::new()?;
        socket.send(buf.as_slice())?;

        // Receive response
        let mut recv_buf = [0u8; 8192];
        loop {
            let recv_len = socket.recv(&mut recv_buf)?;
            if recv_len < 16 {
                return Err(io::Error::other("incomplete netlink message received"));
            }

            if let Some(error) = parse_nlmsg_error(&recv_buf[..recv_len]) {
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(-error));
                }
            }

            if is_nlmsg_done(&recv_buf[..recv_len]) {
                break;
            }

            if get_nlmsg_type(&recv_buf[..recv_len]) == Some(NLMSG_ERROR) {
                break;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn nftables_add_element(
        family: &str,
        table: &str,
        setname: &str,
        key: &[u8],
        timeout_secs: u32,
    ) -> io::Result<()> {
        let element = NftElement {
            key: key.to_vec(),
            timeout_secs,
        };

        nftables_add_elements(family, table, setname, &[element])
    }
}

#[cfg(target_os = "linux")]
#[allow(unused_imports, dead_code)]
pub use linux_impl::{nftables_add_element, nftables_add_elements, NftElement};

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
mod non_linux_impl {
    use super::*;

    #[derive(Clone, Debug)]
    pub struct NftElement {
        pub key: Vec<u8>,
        pub timeout_secs: u32,
    }

    #[allow(dead_code)]
    pub fn nftables_add_element(
        _family: &str,
        _table: &str,
        _setname: &str,
        _key: &[u8],
        _timeout_secs: u32,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nftables operations are only supported on Linux",
        ))
    }

    pub fn nftables_add_elements(
        _family: &str,
        _table: &str,
        _setname: &str,
        _elements: &[NftElement],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nftables operations are only supported on Linux",
        ))
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(unused_imports, dead_code)]
pub use non_linux_impl::{nftables_add_element, nftables_add_elements, NftElement};
