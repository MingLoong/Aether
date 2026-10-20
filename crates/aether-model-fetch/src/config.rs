/// 后台目录轮询周期：每 6 小时轮到一个账号；每轮只拉一个 key。
const MODEL_FETCH_INTERVAL_MINUTES_DEFAULT: u64 = 360;
const MODEL_FETCH_INTERVAL_MINUTES_MIN: u64 = 60;
const MODEL_FETCH_INTERVAL_MINUTES_MAX: u64 = 10080;
const MODEL_FETCH_STARTUP_DELAY_SECONDS_DEFAULT: u64 = 10;

pub fn model_fetch_interval_minutes() -> u64 {
    std::env::var("MODEL_FETCH_INTERVAL_MINUTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| {
            value.clamp(
                MODEL_FETCH_INTERVAL_MINUTES_MIN,
                MODEL_FETCH_INTERVAL_MINUTES_MAX,
            )
        })
        .unwrap_or(MODEL_FETCH_INTERVAL_MINUTES_DEFAULT)
}

pub fn model_fetch_startup_enabled() -> bool {
    std::env::var("MODEL_FETCH_STARTUP_ENABLED")
        .ok()
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

pub fn model_fetch_startup_delay_seconds() -> u64 {
    std::env::var("MODEL_FETCH_STARTUP_DELAY_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(MODEL_FETCH_STARTUP_DELAY_SECONDS_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::{
        model_fetch_interval_minutes, model_fetch_startup_delay_seconds,
        model_fetch_startup_enabled,
    };

    struct TestEnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl Drop for TestEnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_deref() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn set_test_env_var(key: &'static str, value: &str) -> TestEnvVarGuard {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        TestEnvVarGuard { key, previous }
    }

    #[test]
    fn interval_minutes_clamps_to_supported_bounds() {
        let _interval = set_test_env_var("MODEL_FETCH_INTERVAL_MINUTES", "5");
        assert_eq!(model_fetch_interval_minutes(), 60);

        let _interval = set_test_env_var("MODEL_FETCH_INTERVAL_MINUTES", "20000");
        assert_eq!(model_fetch_interval_minutes(), 10080);
    }

    #[test]
    fn startup_flags_read_from_environment() {
        let _enabled = set_test_env_var("MODEL_FETCH_STARTUP_ENABLED", "false");
        let _delay = set_test_env_var("MODEL_FETCH_STARTUP_DELAY_SECONDS", "3");
        assert!(!model_fetch_startup_enabled());
        assert_eq!(model_fetch_startup_delay_seconds(), 3);
    }
}
