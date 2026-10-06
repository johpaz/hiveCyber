use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Detecta bucles atascados del agente (LLM llamando la misma herramienta con
/// los mismos argumentos repetidamente).
///
/// La firma compuesta por `name + args_signature` distingue un bucle real
/// (misma tool + mismos args) de invocaciones legítimas repetidas con payloads
/// distintos (p.ej. guardar 5 drafts con `bugcrowd_save_finding_draft`). Sin
/// esta distinción, el detector disparaba falsos positivos cuando el agente
/// iteraba sobre contenido.
pub struct StuckLoopDetector {
    /// Firma compuesta "name\u{1f}args_hash" de la última llamada.
    last_signature: Option<String>,
    /// Veces consecutivas que se ha repetido exactamente la misma firma.
    consecutive_repeat: u32,
    /// Iteraciones consecutivas sin tool calls.
    idle_iterations: u32,
    /// Umbral de repeticiones exactas antes de declarar bucle. 3 es un buen
    /// equilibrio: una repetición es normal (reintentar), dos es sospechosa,
    /// tres indica claramente que el LLM está iterando sin progresar.
    threshold: u32,
}

impl Default for StuckLoopDetector {
    fn default() -> Self {
        StuckLoopDetector {
            last_signature: None,
            consecutive_repeat: 0,
            idle_iterations: 0,
            threshold: 3,
        }
    }
}

impl StuckLoopDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construye la firma compuesta a partir del nombre de la herramienta y un
    /// hash estable de su payload serializado como JSON. El hash usa
    /// `DefaultHasher` (no criptográfico) — solo buscamos detectar repeticiones
    /// exactas, no resistir colisiones adversariales.
    fn signature(name: &str, args_signature: &str) -> String {
        format!("{}\u{1f}{}", name, args_signature)
    }

    /// Registra una llamada a herramienta. Retorna `Some(mensaje)` cuando se
    /// detecta un bucle atascado (misma herramienta + mismos args repetidos
    /// `threshold` veces consecutivas).
    ///
    /// Nota: invocaciones del mismo tool-name con payloads DISTINTOS NO
    /// disparan el detector. Eso es comportamiento legítimo (un worker puede
    /// llamar `bugcrowd_save_finding_draft` 5 veces con 5 drafts distintos).
    pub fn record_tool_call(&mut self, name: &str, args_signature: &str) -> Option<String> {
        let sig = Self::signature(name, args_signature);
        if Some(&sig) == self.last_signature.as_ref() {
            self.consecutive_repeat += 1;
            if self.consecutive_repeat >= self.threshold {
                return Some(format!(
                    "Bucle atascado detectado: herramienta '{}' repetida {} veces consecutivas con los mismos argumentos.",
                    name, self.consecutive_repeat
                ));
            }
        } else {
            self.consecutive_repeat = 0;
        }
        self.last_signature = Some(sig);
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

/// Calcula un hash estable (u64) para un valor JSON serializado. Se usa para
/// que el `loop_runner` pueda computar el `args_signature` barato sin incluir
/// el payload completo en la firma (que podría ser muy grande).
pub fn hash_args(args_json: &str) -> String {
    let mut hasher = DefaultHasher::new();
    args_json.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
