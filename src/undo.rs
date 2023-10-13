use std::collections::HashMap;
use std::collections::VecDeque;



pub struct UndoEntry<T, S> 
{
    pub comment: String,
    pub f: Box<dyn FnMut(& mut HashMap<T,S>) -> bool>,
}

impl<T, S> UndoEntry<T, S> {
    pub fn new(c: &String, func: Box<dyn FnMut(&mut HashMap<T, S>) -> bool>) -> UndoEntry<T, S> {
        return UndoEntry::<T, S> {
            comment: c.clone(),
            f: func,
        };
    }
}

pub struct UndoRepo<T, S> {
    stack: VecDeque<UndoEntry<T, S>>
}

impl<T, S> UndoRepo<T, S> {
    pub fn new() -> UndoRepo<T, S> {
        return UndoRepo { stack: VecDeque::new() }
    }

    // false means undo has failed
    pub fn undo_one(&mut self, state: &mut HashMap<T, S>) -> (String, bool) {
        let mut comment = String::new();

        let call_res = match self.stack.pop_back() {
            Some(mut e) => {
                comment = e.comment;
                (e.f)(state)
            },
            _ => true
        };

        return (comment, call_res)
    }

    pub fn clear(&mut self) {
        self.stack.clear();
    }

    pub fn get_comments(&self) -> Vec<String> {
        let mut res = Vec::<String>::new();
        
        for e in self.stack.iter() {
            res.push(e.comment.clone());
        }

        return res;
    }

    pub fn push(&mut self, c: &String, func: Box<dyn FnMut(&mut HashMap<T, S>) -> bool>) {
        self.stack.push_back(UndoEntry::new(c, func));
    }

    pub fn is_all_undone(&self) -> bool {
        return self.stack.is_empty();
    }
}