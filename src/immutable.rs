use std::fs;
use std::io;

#[allow(dead_code)]
pub fn make_readonly(path: &str) {
    let mut perms = fs::metadata(path).expect("erro metadata").permissions();

    perms.set_readonly(true);

    fs::set_permissions(path, perms).expect("erro setando readonly");
}

#[allow(dead_code)]
pub fn name_file() -> String {
    let mut file = String::new();

    println!("digite o nome do arquivo:");
    io::stdin().read_line(&mut file).expect("erro lendo input");

    let textclean = file.trim().to_string();

    println!("Original: {:?}", file);
    println!("Limpo: {:?}", textclean);

    textclean
}

#[allow(dead_code)]
pub fn without_perms(path: &str) {
    let mut perms = fs::metadata(path).expect("erro metadata").permissions();

    perms.set_readonly(false);

    fs::set_permissions(path, perms).expect("erro setando readonly");
}
