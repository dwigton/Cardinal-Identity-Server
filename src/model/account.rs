use base64::{decode, encode};
use clear_on_drop::clear::Clear;
use database::schema::account;
use database::MyConnection;
use diesel::prelude::*;
use diesel::update;
use encryption::byte_encryption::{decrypt_32, encrypt_32};
use encryption::signing_key::verify_signature;
use encryption::signing_key::SigningKey;
use encryption::{
    check_password, hash_password, hash_salted_password, pk_bytes, random_int_256, secure_hash,
};
use encryption::{decode_32, decode_64, to_512};
use error::{CommonError, CommonResult};
use model::application::Application;
use model::application::PortableApplication;
use model::{Signable, Signed};
use model::{Certifiable, Certified};

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
    pub encrypted_master_key: Vec<u8>,
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
    pub encrypted_master_key: Vec<u8>,
    pub is_admin: bool,
}

//#[derive(Debug)]
pub struct UnlockedAccount {
    pub id: i32,
    pub name: String,
    pub password_hash: String,
    pub export_key_hash: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub master_key_salt: Vec<u8>,
    pub encrypted_master_key: Vec<u8>,
    pub is_admin: bool,
    master_key: [u8; 32],
    signing_key: SigningKey,
}

impl Account {
    pub fn new(name: &str, password: &str, export_key: &str, is_admin: bool) -> NewAccount {
        NewAccount::with_key(name, password, export_key, SigningKey::new(), is_admin)
    }

    pub fn load_locked(name: &str, connection: &MyConnection) -> CommonResult<LockedAccount> {
        Ok(account::table
            .filter(account::name.eq(name))
            .first(connection)?)
    }

    pub fn load_unlocked(
        name: &str,
        password: &str,
        connection: &MyConnection,
    ) -> CommonResult<UnlockedAccount> {
        Account::load_locked(name, connection)?.to_unlocked(password)
    }

    pub fn delete_id(id: &i32, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(account::table.filter(account::id.eq(id))).execute(connection)?;
        Ok(())
    }

    pub fn load_all(connection: &MyConnection) -> CommonResult<Vec<LockedAccount>> {
        Ok(account::table.load(connection)?)
    }
}

impl NewAccount {
    pub fn with_key(
        name: &str,
        password: &str,
        export_key: &str,
        signing_key: SigningKey,
        is_admin: bool,
    ) -> NewAccount {
        let master_key_salt = random_int_256().to_vec();
        let master_encryption_key = hash_salted_password(password, &master_key_salt);
        let master_key = random_int_256();
        let encrypted_master_key = encrypt_32(&master_key, &master_encryption_key).to_vec();
        let encrypted_private_key = signing_key.encrypted_private_key(&master_key).to_vec();
        let password_hash = hash_password(password);
        let export_key_hash = hash_password(export_key);
        let public_key = signing_key.public_key().to_vec();

        NewAccount {
            name: name.to_owned(),
            password_hash,
            export_key_hash,
            public_key,
            encrypted_private_key,
            master_key_salt,
            encrypted_master_key,
            is_admin,
        }
    }

    pub fn from_portable(
        name: &str,
        password: &str,
        export_key: &str,
        import_passphrase: &str,
        import: &PortableAccount,
    ) -> CommonResult<NewAccount> {
        let encryption_key =
            hash_salted_password(import_passphrase, &decode(&import.private_key_salt)?);

        let signing_key = SigningKey::from_encrypted(
            &encryption_key,
            &decode_32(&import.public_key)?,
            &decode_64(&import.encrypted_private_key)?,
        )?;

        Ok(NewAccount::with_key(
            name,
            password,
            export_key,
            signing_key,
            false,
        ))
    }

    pub fn save(&self, connection: &MyConnection) -> CommonResult<LockedAccount> {
        Ok(diesel::insert_into(account::table)
            .values(self)
            .get_result(connection)?)
    }
}

impl LockedAccount {
    pub fn to_unlocked(&self, password: &str) -> CommonResult<UnlockedAccount> {
        if !check_password(password, &self.password_hash) {
            return Err(CommonError::CouldNotAuthenticate(None));
        }

        let master_encryption_key = hash_salted_password(password, &self.master_key_salt);
        let master_key = decrypt_32(to_512(&self.encrypted_master_key), &master_encryption_key)?;

        let signing_key = SigningKey::from_encrypted(
            &master_key,
            &pk_bytes(&self.public_key),
            &to_512(&self.encrypted_private_key),
        )?;

        Ok(UnlockedAccount {
            id: self.id,
            name: self.name.clone(),
            password_hash: self.password_hash.clone(),
            export_key_hash: self.export_key_hash.clone(),
            public_key: self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            master_key_salt: self.master_key_salt.clone(),
            encrypted_master_key: self.encrypted_master_key.clone(),
            is_admin: self.is_admin,
            master_key,
            signing_key,
        })
    }

    pub fn verify_record(&self, record: &impl Signed) -> bool {
        verify_signature(&self.public_key, &record.record_hash(), &record.signature())
    }

    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        update(account::table.filter(account::id.eq(&self.id)))
            .set(self)
            .get_result::<LockedAccount>(connection)?;
        Ok(())
    }
}

impl From<UnlockedAccount> for LockedAccount {
    fn from(unlocked: UnlockedAccount) -> LockedAccount {
        LockedAccount {
            id: unlocked.id,
            name: unlocked.name.clone(),
            password_hash: unlocked.password_hash.clone(),
            export_key_hash: unlocked.export_key_hash.clone(),
            public_key: unlocked.public_key.clone(),
            encrypted_private_key: unlocked.encrypted_private_key.clone(),
            master_key_salt: unlocked.master_key_salt.clone(),
            encrypted_master_key: unlocked.encrypted_master_key.clone(),
            is_admin: unlocked.is_admin,
        }
    }
}

impl UnlockedAccount {
    pub fn to_portable(
        &self,
        export_key: &str,
        passphrase: &str,
        _connection: &MyConnection,
    ) -> CommonResult<PortableAccount> {
        if !check_password(export_key, &self.export_key_hash) {
            return Err(CommonError::CouldNotAuthenticate(None));
        }

        let private_key_salt = random_int_256();
        let encryption_key = hash_salted_password(passphrase, &private_key_salt);
        let encrypted_private_key = self.signing_key.encrypted_private_key(&encryption_key);

        let applications = Vec::new();

        Ok(PortableAccount {
            public_key: encode(&self.public_key),
            private_key_salt: encode(&private_key_salt),
            encrypted_private_key: encode(&encrypted_private_key.to_vec()),
            applications: applications,
        })
    }

    pub fn sign_record<T: Signed>(&self, record: &impl Signable<T>) -> T {
        let signature = self.sign(&record.record_hash());
        record.sign(signature)
    }

    pub fn certify_record<T: Certified>(&self, record: &impl Certifiable<T>) -> T {
        let signature = self.sign(&record.data().hash());
        record.certify(self.public_key, signature)
    }

    pub fn verify_record(&self, record: &impl Signed) -> bool {
        self.verify(&record.record_hash(), &record.signature())
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data)
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        self.signing_key.verify(data, signature)
    }

    pub fn generate_key(&self, salt: &[u8]) -> [u8; 32] {
        secure_hash(&[&self.master_key, salt])
    }

    pub fn change_password(
        mut self,
        new_password: &str,
        connection: &MyConnection,
    ) -> CommonResult<()> {
        // first all associated records need to be unlocked and stored.

        self.master_key_salt = random_int_256().to_vec();
        let master_encryption_key = hash_salted_password(new_password, &self.master_key_salt);
        self.encrypted_master_key = encrypt_32(&self.master_key, &master_encryption_key).to_vec();
        self.encrypted_private_key = self
            .signing_key
            .encrypted_private_key(&self.master_key)
            .to_vec();
        self.password_hash = hash_password(&new_password);

        self.save(connection)

        // with an encrypted master key, all associated records no longer need to be re-keyed with
        // a password change.
    }

    pub fn save(self, connection: &MyConnection) -> CommonResult<()> {
        let locked: LockedAccount = self.into();
        locked.save(connection)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        let applications = Application::load_all_for_account(&self, connection)?;
        for app in applications {
            app.delete(connection)?;
        }
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
        let account = Account::new("Test01", "password", "passphrase", false);

        let locked = account.save(&connection).expect("could not save");

        let loaded =
            Account::load_locked("Test01", &connection).expect("could not load from database");

        assert_eq!(locked, loaded);

        let unlocked = loaded
            .to_unlocked("password")
            .expect("Could no unlock for deletion.");

        match unlocked.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn sign_and_verify() {
        let connection = establish_connection().unwrap();
        let account = Account::new("Test04", "password", "passphrase", false);

        let locked = account.save(&connection).expect("Could not save");
        let unlocked = locked.to_unlocked("password").expect("Could not unlock");

        let message = b"Please sign and return";

        let sig = unlocked.sign(message);

        let valid = unlocked.verify(message, &sig);

        match unlocked.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }

        assert!(valid);
    }

    #[test]
    fn unlock_account() {
        let connection = establish_connection().unwrap();
        let account = Account::new("Test02", "password", "passphrase", false);

        let locked = account.save(&connection).expect("Could not save");
        let unlocked = locked.to_unlocked("password").expect("Could not unlock");

        let unlocked_loaded = Account::load_unlocked("Test02", "password", &connection)
            .expect("could not load from database");

        let message = b"Please sign and return";

        let sig = unlocked.sign(message);
        let valid = unlocked_loaded.verify(message, &sig);

        assert_eq!(unlocked.id, unlocked_loaded.id);
        assert_eq!(unlocked.name, unlocked_loaded.name);
        assert_eq!(unlocked.password_hash, unlocked_loaded.password_hash);
        assert_eq!(unlocked.export_key_hash, unlocked_loaded.export_key_hash);
        assert_eq!(unlocked.public_key, unlocked_loaded.public_key);
        assert_eq!(
            unlocked.encrypted_private_key,
            unlocked_loaded.encrypted_private_key
        );
        assert_eq!(unlocked.master_key_salt, unlocked_loaded.master_key_salt);
        assert_eq!(unlocked.is_admin, unlocked_loaded.is_admin);

        match unlocked.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }

        assert!(valid);
    }

    #[test]
    fn change_password() {
        let connection = establish_connection().unwrap();
        let account = Account::new("Test03", "password", "passphrase", false);

        let locked = account.save(&connection).expect("could not save");
        let unlocked = locked.to_unlocked("password").expect("Could not unlock");

        let message = b"Please sign and return";
        let sig = unlocked.sign(message);

        unlocked
            .change_password("new_password", &connection)
            .expect("Could not change password");

        let locked_loaded =
            Account::load_locked("Test03", &connection).expect("could not load from database");
        let unlocked_loaded = locked_loaded
            .to_unlocked("new_password")
            .expect("Could not unlock");

        let verified = unlocked_loaded.verify(message, &sig);

        match unlocked_loaded.delete(&connection) {
            Ok(_) => (),
            Err(_) => panic!(),
        }

        assert!(verified);
    }
}
