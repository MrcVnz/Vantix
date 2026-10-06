//! Justified paragraphs. Slint can't justify text, so lines are broken here with the
//! advance widths of the font Slint draws with, and the UI spreads each line's words.

use std::sync::OnceLock;

/// The UI font, see `default-font-family` in ui/app.slint. Its default instance is the
/// "Text" optical size at regular weight, which is what Slint renders.
const FONT: &str = "SegUIVar.ttf";

pub struct Line {
    pub words: Vec<String>,
    /// The last line of a paragraph isn't stretched.
    pub last: bool,
}

/// Breaks `text` into lines no wider than `width` at `size`, both in logical pixels.
/// `None` when the font can't be read, so the caller falls back to normal wrapping.
pub fn justify(text: &str, size: f32, width: f32) -> Option<Vec<Line>> {
    let font = font()?;
    let face = ttf_parser::Face::parse(font, 0).ok()?;
    let scale = size / f32::from(face.units_per_em());
    let measure = |word: &str| -> f32 {
        word.chars()
            .map(|c| {
                face.glyph_index(c)
                    .and_then(|glyph| face.glyph_hor_advance(glyph))
                    .map_or(f32::from(face.units_per_em()) / 2.0, f32::from)
            })
            .sum::<f32>()
            * scale
    };
    let space = measure(" ");

    let mut lines = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut used = 0.0;
    for word in text.split_whitespace() {
        let w = measure(word);
        if !words.is_empty() && used + space + w > width {
            lines.push(Line { words: std::mem::take(&mut words), last: false });
            used = 0.0;
        }
        used += if words.is_empty() { w } else { space + w };
        words.push(word.to_string());
    }
    if !words.is_empty() {
        lines.push(Line { words, last: true });
    }
    Some(lines)
}

fn font() -> Option<&'static [u8]> {
    static DATA: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut buffer = [0u16; 260];
        let len =
            unsafe { windows::Win32::System::SystemInformation::GetWindowsDirectoryW(Some(&mut buffer)) };
        let dir = String::from_utf16_lossy(&buffer[..(len as usize).min(buffer.len())]);
        std::fs::read(format!(r"{dir}\Fonts\{FONT}")).ok()
    })
    .as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_fit_and_keep_every_word() {
        let text = "Você usa o Vantix por sua conta e risco. O software é fornecido como está, sem garantia de qualquer tipo.";
        let Some(lines) = justify(text, 13.0, 200.0) else { return };
        assert!(lines.len() > 1);
        assert!(lines.last().unwrap().last && lines.iter().filter(|l| l.last).count() == 1);
        let rejoined: Vec<String> = lines.iter().flat_map(|l| l.words.clone()).collect();
        assert_eq!(rejoined.join(" "), text);
    }
}
