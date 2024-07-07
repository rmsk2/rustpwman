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


use std::collections::HashMap;
use std::collections::VecDeque;


pub struct UndoEntry<T, S> 
{
    pub comment: String,
    pub f: Box<dyn FnMut(& mut HashMap<T,S>) -> bool + Send + Sync>,
}

impl<T, S> UndoEntry<T, S> {
    pub fn new(c: &String, func: Box<dyn FnMut(&mut HashMap<T, S>) -> bool + Send + Sync>) -> UndoEntry<T, S> {
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

    pub fn push(&mut self, c: &String, func: Box<dyn FnMut(&mut HashMap<T, S>) -> bool + Send + Sync>) {
        self.stack.push_back(UndoEntry::new(c, func));
    }

    pub fn is_all_undone(&self) -> bool {
        return self.stack.is_empty();
    }
}