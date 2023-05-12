use crate::consts;

pub struct AES128 {
    key: [[u8;4];44],
}

impl AES128 {
    pub fn new(key: String) -> AES128 {
        let bytes = key.as_bytes();
        if bytes.len() != 16 {
            panic!("16 bytes key is needed");
        }

        AES128 {
            key: expand_key(&AES128::key_into(bytes))
        }
    }
    fn key_into<A,T>(slice: &[T]) -> A
    where  A: Default + AsMut<[T]>,
           T: Clone,
    {
        let mut a = A::default();
        <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
        a
    }
    pub fn encrypt(&self, bytes: &[u8]) -> Vec<u8> {
        if bytes.len() % 16 != 0 {
            panic!("This could be your ad about 16 bytes of enc text");
        }

        let mut res = vec![0u8; bytes.len()];

        for i in 0..bytes.len()/16 {
            let mut block = [0u8;16];
            for j in 0..16 {
                block[j] = bytes[i*16 + j];
            }
            block = self.encrypt_block(&block);
            for j in 0..16 {
                res[i*16 + j] = block[j];
            }
        }
        res
    }
    fn encrypt_block(&self, block: &[u8;16]) -> [u8;16] {
        let mut res = [0u8;16];
        let mut state = [[0u8;4];4];

        for i in 0..16 {
            state[i%4][i/4] = block[i];
        }
        state = add_round_key(&state, &AES128::key_into(&self.key[0..4]));
        for i in 1..10 {
            state = sub_bytes(&state);
            state = shift_rows(&state);
            state = mix_columns(&state);
            state = add_round_key(&state, &AES128::key_into(&self.key[i*4..(i+1)*4]));
        }

        state = sub_bytes(&state);
        state = shift_rows(&state);
        state = add_round_key(&state, &AES128::key_into(&self.key[40..44]));
        for i in 0..4 {
            for j in 0..4 {
                res[4*j+i] = state[i][j]
            }
        }
        res
    }

    pub fn decrypt(&self, bytes: &[u8]) -> Vec<u8> {
        if bytes.len()%16!=0 {
            panic!("This could be your ad about 16 bytes of enc text");
        }

        let mut res = vec![0u8; bytes.len()];

        for i in 0..bytes.len()/16 {
            let mut block = [0u8;16];
            for j in 0..16 {
                block[j] = bytes[i*16 + j];
            }
            block = self.decrypt_block(&block);
            for j in 0..16 {
                res[i*16 + j] = block[j];
            }
        }

        res
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut res = [0u8;16];

        let mut state = [[0u8;4];4];
        for i in 0..16 {
            state[i%4][i/4] = block[i];
        }

        state = add_round_key(&state, &AES128::key_into(&self.key[40..44]));
        state = inv_shift_rows(&state);
        state = inv_sub_bytes(&state);

        for i in (1..10).rev() {
            state = add_round_key(&state, &AES128::key_into(&self.key[i*4..(i+1)*4]));
            state = inv_mix_columns(&state);
            state = inv_shift_rows(&state);
            state = inv_sub_bytes(&state);
        }

        state = add_round_key(&state, &AES128::key_into(&self.key[0..4]));

        for i in 0..4 {
            for j in 0..4 {
                res[4*j+i] = state[i][j]
            }
        }

        res
    }
}

fn expand_key(bytes: &[u8;16]) -> [[u8;4];44] {
    let mut original_key = [[0u8;4];4];
    let mut expanded_key = [[0u8;4];44];
    let N = 4;

    for i in 0..16 {
        original_key[i/4][i%4] = bytes[i];
    }

    for i in 0..44 {
        if i < N {
            expanded_key[i] = original_key[i];
        } else if  i >= N && i % N == 0 {
            let mut rcon = [0u8;4];
            rcon[0] = consts::RC[i/N];
            expanded_key[i] = xor_words(&xor_words(&expanded_key[i-N], &sub_word(&rotate_word(&expanded_key[i-1]))), &rcon);
        } else {
            expanded_key[i] = xor_words(&expanded_key[i-N],&expanded_key[i-1]);
        }
    }

    expanded_key
}

fn xor_words(word1_bytes: &[u8; 4], word2_bytes: &[u8; 4]) -> [u8;4] {
    let mut res = [0u8;4];
    for i in 0..4 {
        res[i] = word1_bytes[i] ^ word2_bytes[i];
    }
    res
}

fn sub_word(word: &[u8; 4]) -> [u8;4] {
    let mut res = [0u8;4];
    for i in 0..4 {
        res[i] = sub(word[i], true);
    }
    res
}

fn sub(byte: u8, is_zalooping: bool) -> u8 {
    let top: usize = ((byte>>4) & 0xF).into();
    let down: usize = (byte & 0xF).into();
    if is_zalooping {
        consts::AES_SBOX[top][down]
    } else {
        consts::INVERSE_AES_SBOX[top][down]
    }
}

fn sub_bytes(state: &[[u8;4];4]) -> [[u8;4];4] {
    let mut new_state = state.clone();
    for i in 0..4 {
        for j in 0..4 {
            new_state[i][j] = sub(new_state[i][j], true);
        }
    }
    new_state
}

fn inv_sub_bytes(state: &[[u8;4];4]) -> [[u8;4];4] {
    let mut new_state = state.clone();
    for i in 0..4 {
        for j in 0..4 {
            new_state[i][j] = sub(new_state[i][j], false);
        }
    }
    new_state
}

fn rotate_word(word: &[u8; 4]) -> [u8;4] {
    let mut res = [0u8;4];
    for i in 0..4 {
        res[i] = word[(i+1)%4];
    }
    res
}

fn shift_rows(state: &[[u8;4];4]) -> [[u8;4];4] {
    let mut new_state = state.clone();
    for i in 1..4 {
        let mut tmp = vec![0u8; i];
        for j in 0..i {
            tmp[j] = new_state[i][j];
        }
        for j in 0..4-i {
            new_state[i][j] = new_state[i][j+i];
        }
        for j in 0..i {
            new_state[i][3-j] = tmp[i-j-1];
        }
    }
    new_state
}

fn inv_shift_rows(state: &[[u8;4];4]) -> [[u8;4];4] {
    let mut new_state = state.clone();
    for i in (1..4).rev() {
        let mut tmp = vec![0u8; i];
        for j in 0..i {
            tmp[j] = new_state[4-i][j];
        }
        for j in 0..4-i {
            new_state[4-i][j] = new_state[4-i][j+i];
        }
        for j in 0..i {
            new_state[4-i][3-j] = tmp[i-j-1];
        }
    }
    new_state
}

fn mix_columns(state: &[[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut new_state = state.clone();
    for i in 0..4 {
        let mut temp = [0u8;4];
        for j in 0..4 {
            temp[j] = new_state[j][i];
        }

        new_state[0][i] =
            finite_field_multi(temp[0], 2)
                ^ finite_field_multi(temp[3], 1)
                ^ finite_field_multi(temp[2], 1)
                ^ finite_field_multi(temp[1], 3);
        new_state[1][i] =
            finite_field_multi(temp[1], 2)
                ^ finite_field_multi(temp[0], 1)
                ^ finite_field_multi(temp[3], 1)
                ^ finite_field_multi(temp[2], 3);
        new_state[2][i] =
            finite_field_multi(temp[2], 2)
                ^ finite_field_multi(temp[1], 1)
                ^ finite_field_multi(temp[0], 1)
                ^ finite_field_multi(temp[3], 3);
        new_state[3][i] =
            finite_field_multi(temp[3], 2)
                ^ finite_field_multi(temp[2], 1)
                ^ finite_field_multi(temp[1], 1)
                ^ finite_field_multi(temp[0], 3);
    }

    new_state
}

fn inv_mix_columns(state: &[[u8;4];4]) -> [[u8;4];4] {
    let mut new_state = state.clone();
    for i in 0..4 {
        let mut temp = [0u8;4];
        for j in 0..4 {
            temp[j] = state[j][i];
        }

        new_state[0][i] =
            finite_field_multi(temp[0], 14)
                ^ finite_field_multi(temp[3], 9)
                ^ finite_field_multi(temp[2], 13)
                ^ finite_field_multi(temp[1], 11);
        new_state[1][i] =
            finite_field_multi(temp[1], 14)
                ^ finite_field_multi(temp[0], 9)
                ^ finite_field_multi(temp[3], 13)
                ^ finite_field_multi(temp[2], 11);
        new_state[2][i] =
            finite_field_multi(temp[2], 14)
                ^ finite_field_multi(temp[1], 9)
                ^ finite_field_multi(temp[0], 13)
                ^ finite_field_multi(temp[3], 11);
        new_state[3][i] =
            finite_field_multi(temp[3], 14)
                ^ finite_field_multi(temp[2], 9)
                ^ finite_field_multi(temp[1], 13)
                ^ finite_field_multi(temp[0], 11);
    }
    new_state
}

fn finite_field_multi(x1: u8, x2: u8) -> u8 {
    let mut p = 0u8;
    let mut high_bit: u8;
    let mut a = x1;
    let mut b = x2;
    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a
        }
        high_bit = a & 0x80;
        a = (a<<1) & 0xFF;
        if high_bit == 0x80 {
            a ^= 0x1b;
        }
        b = (b>>1) & 0xFF;
    }
    p & 0xFF
}

fn add_round_key(state:&[[u8; 4]; 4], key: &[[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut new_state = state.clone();
    for i in 0..4 {
        for j in 0..4 {
            new_state[i][j] = new_state[i][j] ^ key[j][i];
        }
    }
    new_state
}
