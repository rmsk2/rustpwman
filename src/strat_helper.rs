use cursive::Cursive;
use cursive::views::{TextArea, SliderView, RadioGroup};
use crate::pwgen;

#[derive(Clone, Copy)]
pub struct StratHelper {
    name_slider_val: &'static str,
    name_pw_len: &'static str,
    name_sec_level: &'static str,
}

impl StratHelper {
    pub fn new(name_slider: &'static str, name_len: &'static str, name_level: &'static str) -> StratHelper {
        return StratHelper { 
            name_slider_val: name_slider, 
            name_pw_len: name_len, 
            name_sec_level: name_level 
        };
    }

    pub fn show_sec_bits(&self, s: &mut Cursive, val: usize, strategy_group: RadioGroup<pwgen::GenerationStrategy>) {
        s.call_on_name(self.name_sec_level, |view: &mut TextArea| {
            let out = format!("{}", (val + 1) * 8);
            view.set_content(out.clone());
        });
        let sel = strategy_group.selection();
        self.calc_char_size(s, &sel, val);
    }

    fn calc_char_size(&self, s: &mut Cursive, selected_strategy: &pwgen::GenerationStrategy, slider_val: usize) {
        let sec_level_in_bits = (slider_val + 1) * 8;
        let generator = selected_strategy.to_creator()();
        let sec_in_chars: usize = generator.sec_level_in_chars(sec_level_in_bits);

        s.call_on_name(self.name_pw_len, |view: &mut TextArea| {
            let out = format!("{}", sec_in_chars);
            view.set_content(out.clone());
        });
    }

    pub fn strat_on_change(&self, s: &mut Cursive, selected_strategy: &pwgen::GenerationStrategy) {
        let rand_bytes = match s.call_on_name(self.name_slider_val, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { return; }
        };

        self.calc_char_size(s, &selected_strategy, rand_bytes);
    }
}

