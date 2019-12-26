TESTS = check_helper check_packet check_node check_connection check_ncot check_shell check_context check_policy check_ring check_db check_keys
check_PROGRAMS = check_helper check_ncot check_node check_connection check_packet check_shell check_context check_policy check_ring check_db check_keys server client ssh2server ssh2client
#check_PROGRAMS = check_context server client

#test_sources = ../src/ncot.h ../src/log.c ../src/connection.c ../src/context.c ../src/node.c ../src/packet.c ../src/  ../src/arg.c ../src/init.c ../src/select.c ../src/shell.c ../src/identity.c ../src/shell_context.c ../src/shell_connection.c ../src/shell_identity.c ../src/shell_node.c ../src/shell_connect.c ../src/policy.c ../src/ring.c
test_sources =

check_helper_SOURCES = check_helper.c ${test_sources}
check_helper_CFLAGS = @CHECK_CFLAGS@
check_helper_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_ncot_SOURCES = check_ncot.c $(test_sources)
check_ncot_CFLAGS = @CHECK_CFLAGS@
check_ncot_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_node_SOURCES = check_node.c $(test_sources)
check_node_CFLAGS = @CHECK_CFLAGS@
check_node_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_connection_SOURCES = check_connection.c $(test_sources)
check_connection_CFLAGS = @CHECK_CFLAGS@
check_connection_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_packet_SOURCES = check_packet.c $(test_sources)
check_packet_CFLAGS = @CHECK_CFLAGS@
check_packet_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_shell_SOURCES = check_shell.c $(test_sources)
check_shell_CFLAGS = @CHECK_CFLAGS@
check_shell_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_context_SOURCES = check_context.c $(test_sources)
check_context_CFLAGS = @CHECK_CFLAGS@
check_context_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_policy_SOURCES = check_policy.c $(test_sources)
check_policy_CFLAGS = @CHECK_CFLAGS@
check_policy_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_ring_SOURCES = check_ring.c $(test_sources)
check_ring_CFLAGS = @CHECK_CFLAGS@
check_ring_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_db_SOURCES = check_db.c $(test_sources)
check_db_CFLAGS = @CHECK_CFLAGS@
check_db_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

check_keys_SOURCES = check_keys.c $(test_sources)
check_keys_CFLAGS = @CHECK_CFLAGS@
check_keys_LDADD = @CHECK_LIBS@ @GNUTLS_LIBS@ @POPT_LIBS@ @UUID_LIBS@ @JSONC_LIBS@ @SSH_LIBS@ ../src/libncot.la

server_SOURCES = server.c
server_LDADD = @GNUTLS_LIBS@

client_SOURCES = client.c
client_LDADD = @GNUTLS_LIBS@

ssh2server_SOURCES = ssh2server.c
ssh2server_LDADD = @SSH2_LIBS@

ssh2client_SOURCES = ssh2client.c
ssh2client_LDADD = @SSH2_LIBS@
