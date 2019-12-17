#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>

#include "log.h"

#define KEYS_FOLDER "/home/tdkuehnel/.ssh/"

static void set_default_keys(ssh_bind sshbind,
                             int rsa_already_set,
                             int dsa_already_set,
                             int ecdsa_already_set) {
    if (!rsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,
                             KEYS_FOLDER "id_rsa");
    }
/*    if (!dsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,
                             KEYS_FOLDER "ssh_host_dsa_key");
    }
    if (!ecdsa_already_set) {
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY,
                             KEYS_FOLDER "ssh_host_ecdsa_key");
    }
*/
}

char *
get_home_dir()
{
	char *homedir = NULL;
	homedir = getenv("HOME");
	if ( homedir == NULL )
		homedir == "";


}

int
ask_pass_callback( const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
	NCOT_LOG_ERROR("ask key\n");
	NCOT_LOG_ERROR("len: %d\n", len);
	if (buf) {
		buf[0] = 'x';
		buf[1] = 'x';
		buf[2] = 'x';
		buf[3] = 'x';
		buf[4] = 'x';
		buf[5] = 'x';
		buf[6] = '\0';
		buf[7] = '\0';
	}
	return 0;
}

int
generate_key()
{
	ssh_key key = NULL;
	ssh_string blob;
	int rv;
	ssh_session session;
	enum ssh_keytypes_e keytype;
	char *keytypechar;

	key = ssh_key_new();
/* Generate a new ED25519 private key file */
	rv = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
/*	rv = ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &key); */
	if (rv != SSH_OK) {
		NCOT_LOG_ERROR("Failed to generate private key\n");
		return -1;
	}

	NCOT_LOG(NCOT_LOG_LEVEL_WARNING, "sshserver: generate_key success \n");

	keytype = ssh_key_type(key);
	keytypechar = (char*)ssh_key_type_to_char(keytype);

	NCOT_LOG(NCOT_LOG_LEVEL_WARNING, "sshserver: key type is: %s \n", keytypechar);
/*	rv = ssh_pki_import_privkey_file("/home/tdkuehnel/.ssh/id_rsa", NULL, ask_pass_callback, NULL, &key);*/

	if (rv != SSH_OK) {
		NCOT_LOG_ERROR("error importing key from file\n");
		NCOT_LOG_ERROR("%s\n", ssh_get_error(session));
	} else {
		NCOT_LOG_INFO("key imported\n");
	}
	if (ssh_key_is_private(key)) {
		NCOT_LOG_INFO("key is private\n");
	} else {
		NCOT_LOG_INFO("key is not a private one\n");
	}

	/* Write it to a file testkey in the current directory */
	rv = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, "testkey");
	if (rv != SSH_OK) {
		NCOT_LOG_ERROR("Failed to write private key file\n");
		return -1;
	}
}


int main(int argc, char **argv)
{
    ssh_bind sshbind;
    ssh_session session;
    int verbosity = SSH_LOG_FUNCTIONS;
    int rc;

    ncot_log_init(NCOT_LOG_LEVEL_INFO);
    rc = ssh_init();
    if (rc < 0) {
        fprintf(stderr, "ssh_init failed\n");
        return 1;
    }

    generate_key();
/*    exit(0);*/

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "ssh_bind_new failed\n");
        return 1;
    }

    (void) argc;
    (void) argv;

    set_default_keys(sshbind, 0, 0, 0);

    ssh_bind_options_set(sshbind, SSH_OPTIONS_LOG_VERBOSITY, "3");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "2244");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "192.168.178.24");

    if(ssh_bind_listen(sshbind) < 0) {
	    fprintf(stderr, "%s\n", ssh_get_error(sshbind));
	    return 1;
    }
    printf("Mark 3\n");

    session = ssh_new();
    if (session == NULL) {
	    fprintf(stderr, "Failed to allocate session\n");
	    return 1;
    }

    /* Blocks until there is a new incoming connection. */
    if(ssh_bind_accept(sshbind, session) != SSH_ERROR) {


    }
    printf("done\n");
}
