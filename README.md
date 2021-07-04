
# Cardinal Identity Server

The Identity Server is the cornerstone of the Cardinal Network Protocol. It acts as a key store for all client applications authorized by the user and handles signing messages and decrypting message keys. Cardinal seeks to give users control of their online identity, this can only be done with the ability to manage their own set of cryptographic keys that proves their identity to the network and enables decryption of messages.

## Data Structure

```
Account
   +-- Application
           +-- Read Grant Scope
           |         +-- Read Grant Key
           +-- Write Grant Scope
           +-- Client
                 +-- Read Authorization
                 +-- Write Authorization
```

All records are signed by the Account to prevent tampering, and can only be read or altered with the password present. Read and write authorizations can unlock Read and Write Grant Keys in order to sign or decrypt data but require the presence of a valid Client Id and Client Secret to unlock.

For now all signing keys are ed25519 and all exchange keys are x25519
 
## Installation

Follow the instructions [here](https://www.rust-lang.org/tools/install) to install the rust tool chain.

The Cardinal Identity Server currently uses postgresql for persistence. If you don't have a postgres server install locally and create an empty database and user. For example database `identity_server` with password `testing`

After cloning the repository run.

```bash
cargo run init
```
You will be prompted to enter a postgres connection string of the form 

`postgres://<username>:<password>@<host>/<database>`

So with our example database and user. 

```bash
DATABASE_URL: postgres://identity_server:testing@localhost/identity_server
```

## Usage

### Running the web application

Generally, the Identity Server will run as a web application. To start the server simply use.
 
```bash
$ cargo run run
```
**Note:** The web application is unfinished at this time, but most features are available via the commandline

### Testing on the commandline

The identity Server has a simple commandline interface to test functionality. In practice only basic administration tasks will be via the cli application.

Create a new user account. This will create and encrypt a new ed21559 Public Key. An export key is a secondary password required to export the users keys in order to move to a new server.

```bash
$ cargo run account add
New account name: test_account
New account password: 
Reenter password:
New account export key:
Reenter export key:
New account "test_account" created successfully.
```

Create keys for an application. This step isn't strictly necessary since keys will be created as permissions are granted for new applications through the API.

```bash
$ cargo run application add
Account name: test_account
Account password:
Application code: test_app
Description: Test Application
Application server url: https://datahost.forapplication.com
Application "test" added successfully.
```

Let's create a few application read and write scopes to post, view, and, delete entries to our Test Application. This example is non-interactive. The previous commands can also be run non-interactively by providing the required arguments see `cargo run help` for details.

```bash
$ cargo run application scope -a test_account -p password -c test_app -w post -w delete -r view
```

Now to authorize an application client.

```bash
$ cargo run client add -a test_account -p password -c test_app -w post -r view
Client P6ezB0JOKgYMvSkhNsv66nY1QQTyQySpYkpWaOu+tjI= for "test_app" added.
Client ID: P6ezB0JOKgYMvSkhNsv66nY1QQTyQySpYkpWaOu+tjI=
Client Secret: GOmkMQY5IkVIk56EU7DwnPEsXt7uHvbyzsnPegSfDEU=
```

The Client ID and Client Secret can then be used to post or view items in the test_app application.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[Affero GPL v3]
