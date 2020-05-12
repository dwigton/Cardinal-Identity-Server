use database::schema::account;
use database::MyConnection;
use diesel::prelude::*;
use diesel::{update, insert_into, result, delete};
use encryption::signing_key::SigningKey;
use encryption::{hash_password, check_password, random_int_256, hash_salted_password, pk_bytes, secure_hash};
use error::{CommonResult, CommonError};
use base64::{encode, decode};
use encryption::Sha512Trunc256;
use model::application::PortableApplication;
use clear_on_drop::clear::Clear;

pub struct PortableAccount {
    pub public_key: String,
    pub private_key_salt: String,
    pub encrypted_private_key: String,
    pub applications: Vec<PortableApplication>,
}

pub struct Account {}

#[derive(Insertable)]
#[table_name = "account"]
pub struct NewAccount {
    pub name: String,
    pub password_hash: String,
    pub export_key_hash: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub master_key_salt: Vec<u8>,
    pub is_admin: bool,
}

#[derive(PartialEq, Debug, Queryable, Identifiable, AsChangeset)]
#[table_name = "account"]
pub struct LockedAccount {
    pub id: i32,
    pub name: String,
    pub password_hash: String,
    pub export_key_hash: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub master_key_salt: Vec<u8>,
    pub is_admin: bool,
}

#[derive(Debug)]
pub struct UnlockedAccount {
    pub id: i32,
    pub name: String,
    pub password_hash: String,
    pub export_key_hash: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub master_key_salt: Vec<u8>,
    pub is_admin: bool,
    master_key: [u8; 32],
    signing_key: SigningKey,
}

impl Account {
    
    pub fn new (name: &str, password: &str, export_key: &str, is_admin: bool) -> NewAccount {

        NewAccount::with_key(name, password, export_key, SigningKey::new(), is_admin)

    }

    pub fn with_name (name: &str, connection: &MyConnection) -> CommonResult<LockedAccount> {
        Ok(account::table.filter( account::name.eq(name)).first(connection)?)
    }

    pub fn delete_id (id: &i32, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(account::table.filter(account::id.eq(id))).execute(connection)?;
        Ok(())
    }

    pub fn load_all (connection: &MyConnection) -> CommonResult<Vec<LockedAccount>> {
        Ok(account::table.load(connection)?)
    }

}

impl NewAccount {

    pub fn with_key(name: &str, password: &str, export_key: &str, signing_key: SigningKey, is_admin: bool) -> NewAccount {

        let master_key_salt       = random_int_256().to_vec();
        let master_key            = hash_salted_password(password, &master_key_salt);
        let encrypted_private_key = signing_key.encrypted_private_key(&master_key);
        let password_hash         = hash_password(password);
        let export_key_hash       = hash_password(export_key);
        let public_key            = signing_key.public_key().to_vec();

        NewAccount {
            name: name.to_owned(),
            password_hash,
            export_key_hash,
            public_key,
            encrypted_private_key,
            master_key_salt,
            is_admin,
        }
    }

    pub fn from_portable (
        name: &str, 
        password: &str, 
        export_key: &str, 
        import_passphrase: &str, 
        import: &PortableAccount) -> CommonResult<NewAccount> {

        let encryption_key = hash_salted_password(import_passphrase, &decode(&import.private_key_salt)?);

        let signing_key = SigningKey::from_encrypted(
            &encryption_key, 
            &pk_bytes(&decode(&import.public_key)?), 
            &decode(&import.encrypted_private_key)?
            )?;

        Ok( 
            NewAccount::with_key(
                name, 
                password, 
                export_key, 
                signing_key, 
                false
        ))
    }

    pub fn save (&self, connection: &MyConnection) -> CommonResult<LockedAccount> {

        Ok(diesel::insert_into(account::table).values(self).get_result(connection)?)

    }
}

impl LockedAccount {
    pub fn to_unlocked(&self, password: &str) -> CommonResult<UnlockedAccount> {
        if !check_password(password, &self.password_hash) {
            return Err(CommonError::CouldNotAuthenticate(None));
        }

        let master_key = hash_salted_password(password, &self.master_key_salt);

        let signing_key = 
            SigningKey::from_encrypted(
                &master_key, 
                &pk_bytes(&self.public_key),
                &self.encrypted_private_key
                )?;
    
        Ok( UnlockedAccount{
            id:                    self.id,
            name:                  self.name.clone(),
            password_hash:         self.password_hash.clone(),
            export_key_hash:       self.export_key_hash.clone(),
            public_key:            self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            master_key_salt:       self.master_key_salt.clone(),
            is_admin:              self.is_admin,
            master_key,
            signing_key,
            })
    }

    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        update(account::table.filter(account::id.eq(&self.id))).set(self).get_result::<LockedAccount>(connection)?;
        Ok(())
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        Account::delete_id(&self.id, connection)
    }
}

impl From<UnlockedAccount> for LockedAccount {
    fn from(unlocked: UnlockedAccount) -> LockedAccount {
        LockedAccount {
            id:                    unlocked.id,
            name:                  unlocked.name.clone(),
            password_hash:         unlocked.password_hash.clone(),
            export_key_hash:       unlocked.export_key_hash.clone(),
            public_key:            unlocked.public_key.clone(),
            encrypted_private_key: unlocked.encrypted_private_key.clone(),
            master_key_salt:       unlocked.master_key_salt.clone(),
            is_admin:              unlocked.is_admin,
        }
    }
}

impl UnlockedAccount {

    pub fn to_portable(&self, export_key: &str, passphrase: &str, connection: &MyConnection) -> CommonResult<PortableAccount> {

        if !check_password(export_key, &self.export_key_hash) {
            return Err(CommonError::CouldNotAuthenticate(None));
        }

        let private_key_salt = random_int_256();
        let encryption_key = hash_salted_password(passphrase, &private_key_salt);
        let encrypted_private_key = self.signing_key.encrypted_private_key(&encryption_key);

        let applications = Vec::new();

        Ok(
        PortableAccount {
            public_key: encode(&self.public_key),
            private_key_salt: encode(&private_key_salt),
            encrypted_private_key: encode(&encrypted_private_key),
            applications: applications,
        })
    }



    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data)
    }

    pub fn generate_key(&self, salt: &[u8]) -> [u8; 32] {
        secure_hash(&[&self.master_key, salt])
    }

    pub fn change_password(mut self, new_password: &str, connection: &MyConnection) -> CommonResult<()> {
        // first all associated records need to be unlocked and stored.
        
        self.master_key_salt      = random_int_256().to_vec();
        let master_key            = hash_salted_password(new_password, &self.master_key_salt);
        self.encrypted_private_key = self.signing_key.encrypted_private_key(&master_key);
        self.password_hash        = hash_password(&new_password);

        self.save(connection)

        // all associated records need to be re-locked with the new master_key.
    }

    pub fn save(self, connection: &MyConnection) -> CommonResult<()> {
        let locked: LockedAccount = self.into();
        locked.save(connection)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        Account::delete_id(&self.id, connection)
    }
}

impl Drop for UnlockedAccount {
    fn drop(&mut self) {
        self.master_key.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database::establish_connection;

    #[test]
    fn create_account() {
        let connection = establish_connection().unwrap();
        let mut account = Account::new(
            "Test01",
            "password",
            "passphrase",
            false
            );

        let locked = account.save(&connection).expect("could not save");

        let mut loaded = Account::with_name("Test01", &connection).expect("could not load from database");

        assert_eq!(locked, loaded);

        match loaded.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn unlock_account() {
        let connection = establish_connection().unwrap();
        let mut account = Account::new(
            "Test02",
            "password",
            "passphrase",
            false
            );

        let locked = account.save(&connection).expect("could not save");
        let unlocked = locked.to_unlocked("password").expect("Could not unlock");

        let mut locked_loaded = Account::with_name("Test02", &connection).expect("could not load from database");
        let unlocked_loaded = locked_loaded.to_unlocked("password").expect("Could not unlock");

        let message = b"Please sign and return";

        let sig1 = unlocked.sign(message);
        let sig2 = unlocked_loaded.sign(message);

        assert_eq!(sig1, sig2);

        match unlocked.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn change_password() {
        let connection = establish_connection().unwrap();
        let mut account = Account::new(
            "Test03",
            "password",
            "passphrase",
            false
            );

        let locked = account.save(&connection).expect("could not save");
        let unlocked = locked.to_unlocked("password").expect("Could not unlock");

        let message = b"Please sign and return";
        let sig1 = unlocked.sign(message);

        unlocked.change_password("new_password", &connection).expect("Could not change password");

        let mut locked_loaded = Account::with_name("Test03", &connection).expect("could not load from database");
        let unlocked_loaded = locked_loaded.to_unlocked("new_password").expect("Could not unlock");

        let sig2 = unlocked_loaded.sign(message);

        assert_eq!(sig1, sig2);

        match unlocked_loaded.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }
    }

}
