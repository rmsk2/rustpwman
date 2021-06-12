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

    let k3 = String::from("test3");
    let v3 = String::from("Doller test3");
    let k4 = String::from("test4");
    let v4 = String::from("Doller test4");


    j.print();
    j.insert(&k3, &v3);
    j.insert(&k4, &v4);
    j.remove(&k4);

    let _ = match j.get(&k3) {
        None => {
            println!("Error did not find expected key");
            return;
        },
        Some(s) => {
            println!("{}: {}", k3, s);
        }
    };

    match j.to_enc_file("safe_test2.enc", "test457") {
        Ok(_) => (),
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };
}
