use std::env;

mod tests;
mod fcrypt;
mod jots;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut j = jots::Jots::new();
    match j.from_enc_file(&args[0], &args[1]) {
        Ok(_) => (),
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };

    j.print();
    j.contents.insert(String::from("test3"), String::from("Doller test3"));

    match j.to_enc_file("safe_test2.enc", "test456") {
        Ok(_) => (),
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
}
