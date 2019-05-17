//! https://github.com/chromium/chromium/blob/master/net/dns/host_resolver_proc.cc#L124

use std::{ mem, ptr, io };
use std::ffi::{ CString, CStr };
use std::net::IpAddr;
use libc::{
    getaddrinfo, freeaddrinfo,
    addrinfo,
    AF_UNSPEC, AI_ADDRCONFIG, SOCK_STREAM
};
use socket2::SockAddr;
use tokio::prelude::*;
use hyper::client::connect::dns;


#[derive(Clone)]
pub struct GaiDnsResolver;

pub struct GaiFuture(dns::Name);

pub struct GaiAddrs {
    original: *mut addrinfo,
    cur: *mut addrinfo
}

impl dns::Resolve for GaiDnsResolver {
    type Addrs = GaiAddrs;
    type Future = GaiFuture;

    fn resolve(&self, name: dns::Name) -> Self::Future {
        GaiFuture(name)
    }
}

impl Future for GaiFuture {
    type Item = GaiAddrs;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let name = CString::new(self.0.as_str())?;
        match tokio_threadpool::blocking(|| resolve(&name)) {
            Ok(Async::Ready(Ok(iter))) => Ok(Async::Ready(iter)),
            Ok(Async::Ready(Err(e))) => Err(e),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

fn resolve(host: &CStr) -> io::Result<GaiAddrs> {
    #[inline]
    fn is_all_loopback_of_one_family(addrinfo: *mut addrinfo) -> bool {
        let mut addrs = GaiAddrs::new(addrinfo);
        let mut flag = false;
        let mut have_ipv4 = false;
        let mut have_ipv6 = false;

        loop {
            match addrs.next() {
                Some(ip) if !ip.is_loopback() => break,
                Some(ip) => {
                    have_ipv4 |= ip.is_ipv4();
                    have_ipv6 |= ip.is_ipv6();
                },
                None => {
                    flag = have_ipv4 != have_ipv6;
                    break;
                }
            }
        }

        // don't free addrinfo
        mem::forget(addrs);
        flag
    }

    let mut ai = ptr::null_mut();
    let mut hints: addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    #[cfg(not(windows))] {
        hints.ai_flags = AI_ADDRCONFIG;
    }

    let mut err = unsafe {
        getaddrinfo(host.as_ptr(), ptr::null(), &hints, &mut ai)
    };

    if (hints.ai_family != AF_UNSPEC || hints.ai_flags == AI_ADDRCONFIG)
        && err == 0 && is_all_loopback_of_one_family(ai)
    {
        hints.ai_flags &= !AI_ADDRCONFIG;
        err = unsafe {
            getaddrinfo(host.as_ptr(), ptr::null(), &hints, &mut ai)
        };
    }

    if err == 0 {
        Ok(GaiAddrs::new(ai))
    } else {
        Err(io::Error::last_os_error())
    }
}

impl GaiAddrs {
    fn new(addr: *mut addrinfo) -> GaiAddrs {
        GaiAddrs { original: addr, cur: addr }
    }
}

impl Iterator for GaiAddrs {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = unsafe { self.cur.as_ref()? };
        self.cur = cur.ai_next;
        let addr = unsafe {
            SockAddr::from_raw_parts(cur.ai_addr, cur.ai_addrlen)
        };

        let ip = addr.as_inet()
            .map(|addr| IpAddr::V4(*addr.ip()))
            .or_else(|| addr.as_inet6()
                .map(|addr| IpAddr::V6(*addr.ip()))
            );

        ip.or_else(|| self.next())
    }
}

impl Drop for GaiAddrs {
    fn drop(&mut self) {
        unsafe { freeaddrinfo(self.original) };
    }
}

unsafe impl Sync for GaiAddrs {}
unsafe impl Send for GaiAddrs {}
