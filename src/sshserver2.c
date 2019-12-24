/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#ifdef HAVE_ARGP_H
#include <argp.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/home/tdkuehnel/.ssh/"
#endif
#endif

#define PORT "2244"
#define USER "myuser"
#define PASSWORD "mypassword"

static int authenticated=0;
static int tries = 0;
static int error = 0;
static ssh_channel chan=NULL;

static int auth_publickey()
{
    authenticated = 1;
    return 1; // authenticated
}

#define SSHD_USER "libssh"
#define SSHD_PASSWORD "libssh"

static int auth_password(const char *user, const char *password)
{
    int cmp;

    cmp = strcmp(user, SSHD_USER);
    if (cmp != 0) {
        return 0;
    }
    cmp = strcmp(password, SSHD_PASSWORD);
    if (cmp != 0) {
        return 0;
    }

    authenticated = 1;
    return 1; // authenticated
}

static int authenticate(ssh_session session) {
    ssh_message message;

    /* name = "\n\nKeyboard-Interactive Fancy Authentication\n"; */
    /* instruction = "Please enter your real name and your password"; */
    /* prompts[0] = "Real name: "; */
    /* prompts[1] = "Password: "; */

    do {
	    message=ssh_message_get(session);
	    if(!message)
		    break;
	    switch(ssh_message_type(message)){
            case SSH_REQUEST_AUTH:
		    switch(ssh_message_subtype(message)){
                    case SSH_AUTH_METHOD_PASSWORD:
			    printf("User %s wants to auth with pass %s\n",
				    ssh_message_auth_user(message),
				    ssh_message_auth_password(message));
			    if(auth_password(ssh_message_auth_user(message),
						    ssh_message_auth_password(message))){
				    ssh_message_auth_reply_success(message,0);
				    ssh_message_free(message);
				    return 1;
			    }
			    ssh_message_auth_set_methods(message,
						    SSH_AUTH_METHOD_PASSWORD |
						    SSH_AUTH_METHOD_NONE |
						    SSH_AUTH_METHOD_PUBLICKEY);
			    // not authenticated, send default message
			    ssh_message_reply_default(message);
			    break;

                    case SSH_AUTH_METHOD_PUBLICKEY:
			    printf("User %s wants to auth with auth method PUBLICKEY\n",
				    ssh_message_auth_user(message));
			    if (auth_publickey()) {
				    ssh_message_auth_reply_success(message,0);
				    ssh_message_free(message);
				    return 1;
                            }
                            ssh_message_auth_set_methods(message,
                                                    SSH_AUTH_METHOD_PASSWORD |
						    SSH_AUTH_METHOD_NONE |
                                                    SSH_AUTH_METHOD_PUBLICKEY);
                            ssh_message_reply_default(message);
			    break;
		    case SSH_AUTH_METHOD_NONE:
			    printf("User %s wants to auth with auth method NONE, success\n",
				    ssh_message_auth_user(message));
			    ssh_message_auth_reply_success(message,0);
			    ssh_message_free(message);
			    authenticated = 1;
			    return 1;
			    break;
		    default:
			    printf("User %s wants to auth with unknown auth %d\n",
				    ssh_message_auth_user(message),
				    ssh_message_subtype(message));
			    ssh_message_auth_set_methods(message,
						    SSH_AUTH_METHOD_PASSWORD |
						    SSH_AUTH_METHOD_NONE |
						    SSH_AUTH_METHOD_PUBLICKEY);
			    ssh_message_reply_default(message);
			    break;
		    }
	    default:
		    ssh_message_auth_set_methods(message,
					    SSH_AUTH_METHOD_PASSWORD |
					    SSH_AUTH_METHOD_NONE |
					    SSH_AUTH_METHOD_PUBLICKEY);
		    ssh_message_reply_default(message);
	    }
	    ssh_message_free(message);
    } while (1);
    return 0;
}

/* static int auth_password(ssh_session session, const char *user, */
/*         const char *password, void *userdata){ */
/*     (void)userdata; */
/*     printf("Authenticating user %s pwd %s\n",user, password); */
/*     if(strcmp(user,USER) == 0 && strcmp(password, PASSWORD) == 0){ */
/*         authenticated = 1; */
/*         printf("Authenticated\n"); */
/*         return SSH_AUTH_SUCCESS; */
/*     } */
/*     if (tries >= 3){ */
/*         printf("Too many authentication tries\n"); */
/*         ssh_disconnect(session); */
/*         error = 1; */
/*         return SSH_AUTH_DENIED; */
/*     } */
/*     tries++; */
/*     return SSH_AUTH_DENIED; */
/* } */

/* static int auth_gssapi_mic(ssh_session session, const char *user, const char *principal, void *userdata){ */
/*     ssh_gssapi_creds creds = ssh_gssapi_get_creds(session); */
/*     (void)userdata; */
/*     printf("Authenticating user %s with gssapi principal %s\n",user, principal); */
/*     if (creds != NULL) */
/*         printf("Received some gssapi credentials\n"); */
/*     else */
/*         printf("Not received any forwardable creds\n"); */
/*     printf("authenticated\n"); */
/*     authenticated = 1; */
/*     return SSH_AUTH_SUCCESS; */
/* } */

static int pty_request(ssh_session session, ssh_channel channel, const char *term,
        int x,int y, int px, int py, void *userdata){
    (void) session;
    (void) channel;
    (void) term;
    (void) x;
    (void) y;
    (void) px;
    (void) py;
    (void) userdata;
    printf("Allocated terminal\n");
    return 0;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata){
    (void)session;
    (void)channel;
    (void)userdata;
    printf("Allocated shell\n");
    return 0;
}
struct ssh_channel_callbacks_struct channel_cb = {
    .channel_pty_request_function = pty_request,
    .channel_shell_request_function = shell_request
};

static ssh_channel new_session_channel(ssh_session session, void *userdata){
    (void) session;
    (void) userdata;
    if(chan != NULL)
        return NULL;
    printf("Allocated session channel\n");
    chan = ssh_channel_new(session);
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(chan, &channel_cb);
    return chan;
}


#ifdef HAVE_ARGP_H
const char *argp_program_version = "libssh server example "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<libssh@libssh.org>";

/* Program documentation. */
static char doc[] = "libssh -- a Secure Shell protocol implementation";

/* A description of the arguments we accept. */
static char args_doc[] = "BINDADDR";

/* The options we understand. */
static struct argp_option options[] = {
    {
        .name  = "port",
        .key   = 'p',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the port to bind.",
        .group = 0
    },
    {
        .name  = "hostkey",
        .key   = 'k',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the host key.",
        .group = 0
    },
    {
        .name  = "dsakey",
        .key   = 'd',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the dsa key.",
        .group = 0
    },
    {
        .name  = "rsakey",
        .key   = 'r',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the rsa key.",
        .group = 0
    },
    {
        .name  = "verbose",
        .key   = 'v',
        .arg   = NULL,
        .flags = 0,
        .doc   = "Get verbose output.",
        .group = 0
    },
    {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
     * know is a pointer to our arguments structure.
     */
    ssh_bind sshbind = state->input;

    switch (key) {
        case 'p':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, arg);
            break;
        case 'd':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, arg);
            break;
        case 'k':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, arg);
            break;
        case 'r':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg);
            break;
        case 'v':
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 1) {
                /* Too many arguments. */
                argp_usage (state);
            }
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg);
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) {
                /* Not enough arguments. */
                argp_usage (state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
#endif /* HAVE_ARGP_H */

int main(int argc, char **argv){
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    ssh_channel chan=0;
    int auth=0;
    /* ssh_event mainloop; */
    int verbosity = SSH_LOG_PACKET;
    int rc;

    /* struct ssh_server_callbacks_struct cb = { */
    /*     .userdata = NULL, */
    /*     .auth_password_function = auth_password, */
    /*     /\* .auth_gssapi_mic_function = auth_gssapi_mic, *\/ */
    /*     .channel_open_request_session_function = new_session_channel */
    /* }; */

    char buf[2048];
    int i;
    int r;

    rc = ssh_init();
    if (rc < 0) {
	    fprintf(stderr, "ssh_init failed\n");
	    return 1;
    }
    sshbind=ssh_bind_new();
    session=ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_CONFIG_DIR, "./");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "127.0.0.1");
    ssh_bind_options_set(sshbind, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

#ifdef HAVE_ARGP_H
    printf("have argp\n");
    /*
     * Parse our arguments; every option seen by parse_opt will
     * be reflected in arguments.
     */
    argp_parse (&argp, argc, argv, 0, 0, sshbind);
#else
    printf("have no argp\n");
    (void) argc;
    (void) argv;
#endif

    if(ssh_bind_listen(sshbind)<0){
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }
    printf("Started sshserver2 on port %s\n", PORT);
    r=ssh_bind_accept(sshbind,session);
    if(r==SSH_ERROR){
        printf("error accepting a connection : %s\n", ssh_get_error(sshbind));
        return 1;
    }
    /* ssh_callbacks_init(&cb); */
    /* ssh_set_server_callbacks(session, &cb); */

    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_GSSAPI_MIC | SSH_AUTH_METHOD_PUBLICKEY);
    /* ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE); */

    /* proceed to authentication */
    auth = authenticate(session);
    if (!auth || !authenticated) {
        printf("Authentication error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        return 1;
    }
    printf("Authentication success\n");

    /* wait for a channel session */
    do {
        message = ssh_message_get(session);
        if(message){
		if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                    ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(message);
                ssh_message_free(message);
                break;
            } else {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        } else {
            break;
        }
    } while(!chan);

    if(!chan) {
        printf("Error: client did not ask for a channel session (%s)\n",
                                                    ssh_get_error(session));
        ssh_finalize();
        return 1;
    }

    rc = ssh_channel_read(chan, buf, 5, 0);
    if (rc != 5)
	    printf("error reading 5 bytes over channel\n");
    else
	    printf("5 bytes read\n");

    /* mainloop = ssh_event_new(); */
    /* ssh_event_add_session(mainloop, session); */

    /* while (!(authenticated && chan != NULL)){ */
    /*     if(error) */
    /*         break; */
    /*     r = ssh_event_dopoll(mainloop, -1); */
    /*     if (r == SSH_ERROR){ */
    /*         printf("Error : %s\n",ssh_get_error(session)); */
    /*         ssh_disconnect(session); */
    /*         return 1; */
    /*     } */
    /* } */
    /* if(error){ */
    /*     printf("Error, exiting loop\n"); */
    /* } else */
    /*     printf("Authenticated and got a channel\n"); */
    /* do{ */
    /*     i=ssh_channel_read(chan,buf, 2048, 0); */
    /*     if(i>0) { */
    /*         ssh_channel_write(chan, buf, i); */
    /*         if (write(1,buf,i) < 0) { */
    /*             printf("error writing to buffer\n"); */
    /*             return 1; */
    /*         } */
    /*         if (buf[0] == '\x0d') { */
    /*             if (write(1, "\n", 1) < 0) { */
    /*                 printf("error writing to buffer\n"); */
    /*                 return 1; */
    /*             } */
    /*             ssh_channel_write(chan, "\n", 1); */
    /*         } */
    /*     } */
    /* } while (i>0); */

    ssh_channel_close(chan);
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}

