table! {
    account (id) {
        id -> Int4,
        name -> Varchar,
        password_hash -> Varchar,
        export_key_hash -> Varchar,
        public_key -> Bytea,
        encrypted_private_key -> Bytea,
        master_key_salt -> Bytea,
        encrypted_master_key -> Bytea,
        is_admin -> Bool,
    }
}

table! {
    application (id) {
        id -> Int4,
        account_id -> Int4,
        code -> Varchar,
        description -> Varchar,
        server_url -> Varchar,
        signature -> Bytea,
    }
}

table! {
    client (client_id) {
        client_id -> Bytea,
        application_id -> Int4,
        signature -> Bytea,
    }
}

table! {
    read_authorization (client_id, read_grant_key_id) {
        client_id -> Bytea,
        read_grant_key_id -> Int4,
        encrypted_access_key -> Bytea,
        public_key -> Bytea,
        signature -> Bytea,
    }
}

table! {
    read_grant_key (id) {
        id -> Int4,
        read_grant_scope_id -> Int4,
        public_key -> Bytea,
        encrypted_private_key -> Bytea,
        private_key_salt -> Bytea,
        expiration_date -> Timestamp,
        signature -> Bytea,
    }
}

table! {
    read_grant_scope (id) {
        id -> Int4,
        application_id -> Int4,
        code -> Varchar,
        display_name -> Nullable<Varchar>,
        description -> Nullable<Varchar>,
        signature -> Bytea,
    }
}

table! {
    write_authorization (client_id, write_grant_scope_id) {
        client_id -> Bytea,
        write_grant_scope_id -> Int4,
        encrypted_access_key -> Bytea,
        public_key -> Bytea,
        signature -> Bytea,
    }
}

table! {
    write_grant_scope (id) {
        id -> Int4,
        application_id -> Int4,
        code -> Varchar,
        display_name -> Nullable<Varchar>,
        description -> Nullable<Varchar>,
        public_key -> Bytea,
        encrypted_private_key -> Bytea,
        private_key_salt -> Bytea,
        expiration_date -> Timestamp,
        signature -> Bytea,
    }
}

joinable!(application -> account (account_id));
joinable!(client -> application (application_id));
joinable!(read_authorization -> client (client_id));
joinable!(read_authorization -> read_grant_key (read_grant_key_id));
joinable!(read_grant_key -> read_grant_scope (read_grant_scope_id));
joinable!(read_grant_scope -> application (application_id));
joinable!(write_authorization -> client (client_id));
joinable!(write_authorization -> write_grant_scope (write_grant_scope_id));
joinable!(write_grant_scope -> application (application_id));

allow_tables_to_appear_in_same_query!(
    account,
    application,
    client,
    read_authorization,
    read_grant_key,
    read_grant_scope,
    write_authorization,
    write_grant_scope,
);
