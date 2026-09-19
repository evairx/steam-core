//! Enumerations representing Steam platform types, guard types, and status codes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The target platform for which authentication tokens are issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum EAuthTokenPlatformType {
    #[default]
    Unknown = 0,
    SteamClient = 1,
    WebBrowser = 2,
    MobileApp = 3,
}

impl From<i32> for EAuthTokenPlatformType {
    fn from(val: i32) -> Self {
        match val {
            1 => Self::SteamClient,
            2 => Self::WebBrowser,
            3 => Self::MobileApp,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for EAuthTokenPlatformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::SteamClient => write!(f, "SteamClient"),
            Self::WebBrowser => write!(f, "WebBrowser"),
            Self::MobileApp => write!(f, "MobileApp"),
        }
    }
}

/// The guard type required to satisfy a two-factor authentication challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum EAuthSessionGuardType {
    #[default]
    Unknown = 0,
    None = 1,
    EmailCode = 2,
    DeviceCode = 3,
    DeviceConfirmation = 4,
    EmailConfirmation = 5,
    MachineToken = 6,
    LegacyMachineAuth = 7,
}

impl From<i32> for EAuthSessionGuardType {
    fn from(val: i32) -> Self {
        match val {
            1 => Self::None,
            2 => Self::EmailCode,
            3 => Self::DeviceCode,
            4 => Self::DeviceConfirmation,
            5 => Self::EmailConfirmation,
            6 => Self::MachineToken,
            7 => Self::LegacyMachineAuth,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for EAuthSessionGuardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::None => write!(f, "None"),
            Self::EmailCode => write!(f, "EmailCode"),
            Self::DeviceCode => write!(f, "DeviceCode (TOTP Authenticator)"),
            Self::DeviceConfirmation => write!(f, "DeviceConfirmation (Mobile App Push)"),
            Self::EmailConfirmation => write!(f, "EmailConfirmation"),
            Self::MachineToken => write!(f, "MachineToken"),
            Self::LegacyMachineAuth => write!(f, "LegacyMachineAuth"),
        }
    }
}

/// Persistence level for the requested session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i32)]
pub enum ESessionPersistence {
    Ephemeral = 0,
    #[default]
    Persistent = 1,
}

/// Standard Steam result codes (`EResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum EResult {
    Ok = 1,
    Fail = 2,
    NoConnection = 3,
    InvalidPassword = 5,
    LoggedInElsewhere = 6,
    InvalidProtocolVer = 7,
    InvalidParam = 8,
    FileNotFound = 9,
    Busy = 10,
    InvalidState = 11,
    AccessDenied = 15,
    Timeout = 16,
    Banned = 17,
    AccountNotFound = 18,
    ServiceUnavailable = 20,
    NotLoggedOn = 21,
    Pending = 22,
    Expired = 27,
    Blocked = 40,
    RateLimitExceeded = 84,
    Unknown(i32),
}

impl From<i32> for EResult {
    fn from(val: i32) -> Self {
        match val {
            1 => Self::Ok,
            2 => Self::Fail,
            3 => Self::NoConnection,
            5 => Self::InvalidPassword,
            6 => Self::LoggedInElsewhere,
            7 => Self::InvalidProtocolVer,
            8 => Self::InvalidParam,
            9 => Self::FileNotFound,
            10 => Self::Busy,
            11 => Self::InvalidState,
            15 => Self::AccessDenied,
            16 => Self::Timeout,
            17 => Self::Banned,
            18 => Self::AccountNotFound,
            20 => Self::ServiceUnavailable,
            21 => Self::NotLoggedOn,
            22 => Self::Pending,
            27 => Self::Expired,
            40 => Self::Blocked,
            84 => Self::RateLimitExceeded,
            other => Self::Unknown(other),
        }
    }
}

impl From<EResult> for i32 {
    fn from(val: EResult) -> Self {
        match val {
            EResult::Ok => 1,
            EResult::Fail => 2,
            EResult::NoConnection => 3,
            EResult::InvalidPassword => 5,
            EResult::LoggedInElsewhere => 6,
            EResult::InvalidProtocolVer => 7,
            EResult::InvalidParam => 8,
            EResult::FileNotFound => 9,
            EResult::Busy => 10,
            EResult::InvalidState => 11,
            EResult::AccessDenied => 15,
            EResult::Timeout => 16,
            EResult::Banned => 17,
            EResult::AccountNotFound => 18,
            EResult::ServiceUnavailable => 20,
            EResult::NotLoggedOn => 21,
            EResult::Pending => 22,
            EResult::Expired => 27,
            EResult::Blocked => 40,
            EResult::RateLimitExceeded => 84,
            EResult::Unknown(n) => n,
        }
    }
}

impl fmt::Display for EResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "k_EResultOK (1)"),
            Self::Fail => write!(f, "k_EResultFail (2)"),
            Self::InvalidPassword => write!(f, "k_EResultInvalidPassword (5)"),
            Self::AccessDenied => write!(f, "k_EResultAccessDenied (15)"),
            Self::Timeout => write!(f, "k_EResultTimeout (16)"),
            Self::AccountNotFound => write!(f, "k_EResultAccountNotFound (18)"),
            Self::RateLimitExceeded => write!(f, "k_EResultRateLimitExceeded (84)"),
            Self::Unknown(n) => write!(f, "EResult ({n})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_type_conversion() {
        assert_eq!(
            EAuthTokenPlatformType::from(2),
            EAuthTokenPlatformType::WebBrowser
        );
        assert_eq!(
            EAuthTokenPlatformType::from(999),
            EAuthTokenPlatformType::Unknown
        );
    }

    #[test]
    fn test_guard_type_display() {
        let guard = EAuthSessionGuardType::DeviceConfirmation;
        assert!(guard.to_string().contains("Mobile App Push"));
    }

    #[test]
    fn test_eresult_conversion() {
        assert_eq!(EResult::from(1), EResult::Ok);
        assert_eq!(EResult::from(5), EResult::InvalidPassword);
        assert_eq!(EResult::from(84), EResult::RateLimitExceeded);
    }
}
