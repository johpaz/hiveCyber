use std::collections::HashMap;

pub struct StuckLoopDetector {
    last_tool_signature: Option<String>,
    consecutive_repeat: u32,
    idle_iterations: u32,
}

impl Default for StuckLoopDetector {
    fn default() -> Self {
        StuckLoopDetector {
            last_tool_signature: None,
            consecutive_repeat: 0,
            idle_iterations: 0,
        }
    }
}

impl StuckLoopDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_tool_call(&mut self, signature: &str) -> Option<String> {
        if Some(signature) == self.last_tool_signature.as_deref() {
            self.consecutive_repeat += 1;
            if self.consecutive_repeat >= 3 {
                return Some(format!(
                    "Bucle atascado detectado: herramienta '{}' repetida {} veces consecutivas.",
                    signature, self.consecutive_repeat
                ));
            }
        } else {
            self.consecutive_repeat = 0;
        }
        self.last_tool_signature = Some(signature.to_string());
        None
    }

    pub fn record_idle(&mut self) -> Option<String> {
        self.idle_iterations += 1;
        if self.idle_iterations >= 3 {
            return Some("Iteracion inactiva repetida sin progreso.".into());
        }
        None
    }

    pub fn reset_idle(&mut self) {
        self.idle_iterations = 0;
    }
}