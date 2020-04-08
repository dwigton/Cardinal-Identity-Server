use database::schema::account;

#[derive(Insertable)]
#[table_name = "account"]
pub struct NewAccount {
    pub name: String,
    pub password_hash: String,
    pub export_key: String,
    pub public_key: [u8; 32],
    pub encrypted_private_key: [u8; 48],
    pub master_key_salt: [u8; 32],
    pub is_admin: bool,
}

#[derive(Queryable)]
#[table_name = "account"]
pub struct LockedAccount {
    pub id: i32,
    pub name: String,
    pub password_hash: String,
    pub export_key: String,
    pub public_key: [u8; 32],
    pub encrypted_private_key: [u8; 48],
    pub master_key_salt: [u8; 32],
    pub is_admin: bool,
}

pub struct UnlockedAccount {
    pub id: i32,
    pub name: String,
    pub password_hash: String,
    pub export_key: String,
    pub public_key: [u8; 32],
    pub encrypted_private_key: [u8; 48],
    pub master_key_salt: [u8; 32],
    pub is_admin: bool,
    master_key: [u8; 32],
}

impl NewAccount {
    pub fn new (name: &str, password: &str, is_admin) -> NewAccount {

    }

    pub fn save (&self, connection: &DbConn) -> CommonResult<LockedAccount> {

    }
}

impl LockedAccount {
    pub fn to_unlocked(&self, password: &str) -> CommonResult<UnlockedAccount> {
    }

    pub fn save(connection: &DbConn) -> CommonResult<()> {
    }
}

impl UnlockedAccount {
    pub fn to_locked(&self) -> LockedAccount {
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
    }

    pub fn generate_key(&self, salt: &[u8]) -> Vec<u8> {
    }

    pub fn change_password(&mut self, new_password: $str) -> CommonResult<()> {
    }
}
