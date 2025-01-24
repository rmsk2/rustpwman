use std::fs;

use cursive::theme::BorderStyle;
use cursive::theme::Palette;
use cursive::theme::Theme;
use cursive::style::Color;
use cursive::With;
use serde::Deserialize;
use serde::Serialize;


#[derive(Serialize, Deserialize)]
struct ThemeFormat {
    shadow: Option<bool>,
    borders: Option<String>,
    colors: Option<ColorsFormat>,
}

#[derive(Serialize, Deserialize)]
struct ColorsFormat {
    background: Option<String>,
    shadow: Option<String>,
    view: Option<String>,
    primary: Option<String>,
    secondary: Option<String>,
    tertiary: Option<String>,
    title_primary: Option<String>,
    title_secondary: Option<String>,
    highlight: Option<String>,
    highlight_inactive: Option<String>,
    highlight_text: Option<String>,
}


pub fn get_theme() -> Result<Theme, serde_json::Error> {
    let theme_file = if let Ok(file) = fs::read_to_string("theme.json") { file } else { return Ok(Theme::retro()); };
    let theme_format: ThemeFormat = serde_json::from_str(theme_file.as_str())?;

    let shadow: bool = theme_format.shadow.unwrap_or(false);
    let borders = parse_borders(theme_format.borders);

    let theme = Theme {
        shadow,
        borders,
        palette: Palette::terminal_default().with(|palette| {
            use cursive::style::PaletteColor::*;
            if let Some(c) = theme_format.colors {
                set_color(&mut palette[Background], c.background);
                set_color(&mut palette[Shadow], c.shadow);
                set_color(&mut palette[View], c.view);
                set_color(&mut palette[Primary], c.primary);
                set_color(&mut palette[Secondary], c.secondary);
                set_color(&mut palette[Tertiary], c.tertiary);
                set_color(&mut palette[TitlePrimary], c.title_primary);
                set_color(&mut palette[TitleSecondary], c.title_secondary);
                set_color(&mut palette[Highlight], c.highlight);
                set_color(&mut palette[HighlightInactive], c.highlight_inactive);
                set_color(&mut palette[HighlightText], c.highlight_text);
            }
        })

    };

    Ok(theme)
}

fn set_color(palette_color: &mut Color, theme_color: Option<String>) {
    if let Some(c) = theme_color {
        if let Some(c) = Color::parse(c.as_str()) {
            *palette_color = c;
        }
    }
}

fn parse_borders(s: Option<String>) -> BorderStyle {
    if let Some(s) = s {
        match s.to_lowercase().as_str() {
            "simple" => return BorderStyle::Simple,
            "outset" => return BorderStyle::Outset,
            _ => return BorderStyle::None
        }
    }
    BorderStyle::None
}
