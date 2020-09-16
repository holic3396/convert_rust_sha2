use bytes::Bytes;

mod hash;

pub fn to_hex_string(byte: &Bytes) -> String {
    byte.to_vec()
        .iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

#[cfg(test)]
mod tests {}
