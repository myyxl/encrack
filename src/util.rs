pub fn format_radix(mut x: u32, radix: u32) -> String {
    let mut result = vec![];
    loop {
        let m = x % radix;
        x = x / radix;
        result.push(std::char::from_digit(m, radix).unwrap());
        if x == 0 {
            break;
        }
    }
    result.into_iter().rev().collect()
}

pub fn get_xml_tag(content: &String, tag: &str) -> String {
    content.split(&format!("<{}>", tag)).collect::<Vec<&str>>()[1].split(&format!("</{}>", tag)).collect::<Vec<&str>>()[0].to_string()
}