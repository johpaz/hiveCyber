pub struct ContextCompiler {
    pub max_history: usize,
}

impl Default for ContextCompiler {
    fn default() -> Self {
        ContextCompiler { max_history: 15 }
    }
}