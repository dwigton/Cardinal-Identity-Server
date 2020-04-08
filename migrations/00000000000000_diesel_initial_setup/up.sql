CREATE TABLE account(
    id                     SERIAL          PRIMARY KEY NOT NULL,
    name                   VARCHAR (256)   UNIQUE      NOT NULL,
    password_hash  		   VARCHAR (256)               NOT NULL,
    export_key_hash        VARCHAR (256)               NOT NULL,
    public_key             BYTEA                       NOT NULL,
    encrypted_private_key  BYTEA                       NOT NULL,
    master_key_salt        BYTEA                       NOT NULL,
    is_admin               BOOL                        NOT NULL	
);

CREATE TABLE application(
	id          SERIAL               PRIMARY KEY NOT NULL,
	name        VARCHAR (256)                    NOT NULL,
    account_id  INT REFERENCES account(id)       NOT NULL,
	server_url  VARCHAR (512)                    NOT NULL
);

CREATE TABLE read_grant_scope(
    id              SERIAL          PRIMARY KEY     NOT NULL,
    application_id  INT REFERENCES application(id)  NOT NULL,
    code            VARCHAR (20)                    NOT NULL,
    display_name    VARCHAR (255),
    description     VARCHAR (1000),
    UNIQUE (code, application_id)
);

CREATE TABLE write_grant_scope(
    id                     SERIAL           PRIMARY KEY    NOT NULL,
    application_id         INT REFERENCES application(id)  NOT NULL,
    code                   VARCHAR (20)                    NOT NULL,
    display_name           VARCHAR (255),
    description            VARCHAR (1000),
    public_key             BYTEA                           NOT NULL,
    encrypted_private_key  BYTEA                           NOT NULL,
    private_key_salt       BYTEA                           NOT NULL,
    expiration_date        TIMESTAMP                       NOT NULL,
    signature              BYTEA                           NOT NULL,
    UNIQUE (code, application_id)
);

CREATE TABLE client(
    id              SERIAL          PRIMARY KEY       NOT NULL,
    name            VARCHAR (256) 					  NOT NULL,
    client_id       BYTEA                             NOT NULL,
    application_id  INT REFERENCES application(id)    NOT NULL,
    UNIQUE (name, application_id)
);

CREATE TABLE read_grant_key(
    id                     SERIAL          PRIMARY KEY          NOT NULL,
    read_grant_scope_id    INT REFERENCES read_grant_scope(id)  NOT NULL,
    public_key             BYTEA                                NOT NULL,
    encrypted_private_key  BYTEA                                NOT NULL,
    private_key_salt       BYTEA                                NOT NULL,
    expiration_date        TIMESTAMP                            NOT NULL,
    signature              BYTEA                                NOT NULL
);

CREATE TABLE read_authorization(
    id                    SERIAL          PRIMARY KEY        NOT NULL,
    client_id             INT REFERENCES client(id)          NOT NULL,
    read_grant_key_id     INT REFERENCES read_grant_key(id)  NOT NULL,
    encrypted_access_key  BYTEA                              NOT NULL,
    public_key            BYTEA                              NOT NULL,
    signature             BYTEA                              NOT NULL
);

CREATE TABLE write_authorization(
    id                    SERIAL          PRIMARY KEY           NOT NULL,
    client_id             INT REFERENCES client(id)             NOT NULL,
    write_grant_scope_id  INT REFERENCES write_grant_scope(id)  NOT NULL,
    encrypted_access_key  BYTEA                                 NOT NULL,
    public_key            BYTEA                                 NOT NULL,
    signature             BYTEA		                            NOT NULL
);
