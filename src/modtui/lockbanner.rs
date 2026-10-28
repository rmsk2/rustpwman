/* Copyright 2021 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use cursive::View;
use cursive::views::Canvas;
use cursive::Vec2;

const GLYPH_H: usize = 7;
const GLYPH_W: usize = 5;
const PX_W: usize = 2;   // terminal cells per pixel; cells are about twice as tall as wide
const GAP: usize = 1;    // pixels between letters

fn glyph(c: char) -> Option<[&'static str; GLYPH_H]> {
    match c {
        'L' => Some(["#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"]),
        'O' => Some([" ### ", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "]),
        'C' => Some([" ####", "#    ", "#    ", "#    ", "#    ", "#    ", " ####"]),
        'K' => Some(["#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"]),
        'E' => Some(["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"]),
        'D' => Some(["#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "]),
        _ => None,
    }
}

// The coordinate system seen by the Canvas has the size returned by with_required_size().
pub fn banner_view(text: &str) -> impl View {
    // Map characters to their pixel patterns. Leave out characters for which there is no pattern
    let glyphs: Vec<[&'static str; GLYPH_H]> = text.chars().filter_map(glyph).collect();
    // Calculate number of printable characters and their combined width in "pixels"
    let n = glyphs.len();
    let width = if n == 0 { 0 } else { (n * GLYPH_W + (n - 1) * GAP) * PX_W };

    Canvas::new(glyphs)
        .with_draw(move |glyphs, printer| {
            // center horizontally in the width we were given
            let x0 = printer.size.x.saturating_sub(width) / 2;

            // Iterate over all characters
            for (i, g) in glyphs.iter().enumerate() {
                // Calculate start offset of current character in x direction (horizontal)
                let gx = x0 + i * (GLYPH_W + GAP) * PX_W;

                // Iterate over current character's rows
                for (y, row) in g.iter().enumerate() {
                    // Iterate over columns of current row
                    for (col, px) in row.chars().enumerate() {
                        // draw "pixels"
                        if px == '#' {
                            // "pixels" on screen are twice as wide as "pixels" in the defining pattern
                            printer.print((gx + col * PX_W, y), "██");
                        }
                    }
                }
            }
        })
        .with_required_size(move |_, _| Vec2::new(width, GLYPH_H))
}